# Server-side execution gate

BACKSTOP includes an embeddable TypeScript execution-gate library. Unlike the browser console, it wraps server-registered tools and runs them only after policy evaluation, resource authorization, request-bound approval where required, a durable one-time execution claim, and a successful pre-execution audit write.

## Install and build locally

Requirements: Node.js 22.12+ and npm (Vitest 5 requires this Node.js version).

```sh
npm install
npm test
npm run check
npm run build
```

## The security flow

1. Your existing server authenticates the caller and provides a trusted `AuthenticatedAgent` object. Never read its ID, organization, or permissions from the request body.
2. Register each executable tool on the server with a fixed BACKSTOP action type, an input parser, and a resource/summary mapper. The browser/client cannot select the action type that represents the registered tool.
3. BACKSTOP snapshots the parsed JSON input, derives an action request from the server-side tool definition, checks the agent's action allowlist, asks the app's resource/tenant ACL, and evaluates the server-loaded policy.
4. A `BLOCK` decision never calls the tool. `REQUIRE_APPROVAL` is durably registered for review and never calls the tool unless approval is atomically verified and consumed for the exact request and payload.
5. Before any allowed tool call, the gate writes an authorization event to the trusted audit sink. If this pre-execution write fails, the action does not run.
6. It then atomically claims the organization's request ID. If that ID was already used, is in progress, or is bound to another payload, no action runs.
7. After execution, the gate attempts to record success or failure. A successful operation can still have `auditComplete: false` if the post-execution audit write fails; this must be treated as an incident. The durable request claim remains in place, preventing automatic replay.

## Important implementation contracts

- `parseInput` must validate input and return a detached canonical value. The gate snapshots and freezes JSON-compatible values.
- `describe` must map the actual tool operation and target to a truthful resource identifier and safe summary; never put tokens, secrets, or personal data in audit text.
- `authorizeResource` must perform the application's actual object-level and organization-level authorization.
- `getRules` must read trusted server-owned policy configuration; never accept arbitrary custom rules from a browser.
- `recordApprovalRequest` must durably save the action metadata, active policy version, request ID, and input digest before the approval-required result is returned. It must be idempotent and reject a reused request ID with a different digest.
- `verifyAndConsumeApproval` must atomically check and consume a persisted, authenticated, unexpired approval bound to the same organization, request, operation, resource, canonical input digest, and reviewer permissions. Concurrent attempts must not both succeed. A read-only check is not enough.
- `claimExecution` must atomically insert a unique `(organization_id, request_id)` record including the digest; return `true` only for the first valid claim. Use a database unique constraint or transaction, not process memory. This conservative gate does not automatically retry a claimed operation after a crash; an operator must inspect the audit trail before recovery.
- `appendAudit` must write to a server-controlled durable store. Browser local storage is not suitable.

Example tool registration:

```ts
const gate = createExecutionGate([{
  name: "documents.read",
  actionType: "read_resource",
  parseInput(value) {
    if (!value || typeof value !== "object" ||
        typeof (value as { documentId?: unknown }).documentId !== "string") {
      throw new Error("Invalid input");
    }
    return { documentId: (value as { documentId: string }).documentId };
  },
  describe(input) {
    return {
      resource: `documents/${input.documentId}`,
      summary: "Read a document",
    };
  },
  async execute(input, { agent }) {
    // Perform the real operation here, using agent-scoped server credentials.
    return await documentService.readForAgent(agent.id, input.documentId);
  },
}], {
  getRules: (agent) => policyStore.loadCurrent(agent.organizationId),
  authorizeResource: ({ agent, resource }) =>
    documentService.canRead(agent.id, resource),
  recordApprovalRequest: (entry) => approvalStore.insertPendingOnce(entry),
  verifyAndConsumeApproval: (verification) => approvalStore.verifyAndConsumeOnceForExactRequest(verification),
  claimExecution: (claim) => executionClaims.insertUnique(claim),
  appendAudit: (event) => auditStore.append(event),
});

// In an authenticated server route, never in browser code:
const result = await gate.invoke({
  requestId: serverGeneratedRequestId,
  agent: authenticatedAgentFromSession,
  toolName: "documents.read",
  input: validatedRequestBody,
});
```

This is an integration library, not a complete hosted security service. A starter PostgreSQL schema is provided at `packages/core/migrations/001_execution_control.sql`, but repository-specific database adapters, migrations applied to a real database, authentication/session adapters, deployment configuration, rate limiting, key rotation, operational monitoring, integration tests against real tools, and independent security review are still required. Do not point real agents at this until your application implements and verifies those pieces.
