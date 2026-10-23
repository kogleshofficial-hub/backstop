# Server-side execution gate

BACKSTOP now includes an embeddable TypeScript execution-gate library. Unlike the browser console, this module wraps a server-registered tool and only invokes it after policy evaluation, a separate resource authorization check, and—when the policy requires it—verification of approval evidence.

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
4. A `BLOCK` decision never calls the tool. `REQUIRE_APPROVAL` never calls the tool unless the approval verifier confirms evidence for that exact request.
5. Before any allowed tool call, the gate writes an authorization event to the trusted audit sink. If this pre-execution write fails, the action does not run.
6. After execution, the gate attempts to record success or failure. A successful operation can still have `auditComplete: false` if the post-execution audit write fails; this must be treated as an incident.

## Important implementation contracts

- `parseInput` must validate input and return a detached canonical value. The gate snapshots and freezes JSON-compatible values.
- `describe` must map the actual tool operation and target to a truthful resource identifier and safe summary; never put tokens, secrets, or personal data in audit text.
- `authorizeResource` must perform the application's actual object-level and organization-level authorization.
- `getRules` must read trusted server-owned policy configuration; never accept arbitrary custom rules from a browser.
- `verifyAndConsumeApproval` must check a persisted, authenticated, unexpired approval bound to the same organization, request, operation, resource, input digest, and reviewer permissions. It should enforce single use/replay protection. The gate checks the request ID match, but your verifier must validate the other binding.
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
  getRules: (agent) => policyStore.loadRules(agent.organizationId),
  authorizeResource: ({ agent, resource }) =>
    documentService.canRead(agent.id, resource),
  verifyAndConsumeApproval: (verification) => approvalStore.verifyAndConsumeOnceForExactRequest(verification),
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

This is a library, not a complete hosted security service. The repository still needs concrete authentication/session adapters, a durable database schema and migration, production deployment configuration, rate limiting, key rotation, operational monitoring, idempotency implementation, integration tests against real adapters, and independent security review. Do not point real agents at this until your application implements and verifies those pieces.
