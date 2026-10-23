# @backstop/core

Deterministic policy evaluation and reusable server-side controls for applications that run AI agents.

## What it provides

- `evaluateAction()`: a pure TypeScript decision engine that returns `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.
- `runPolicyScenarios()`: a model-free way to test expected decisions and detect policy regressions.
- `createExecutionGate()`: a wrapper around server-registered tool calls. It checks action scope, resource authorization, policy version, approval evidence, pre-execution audit, and a durable one-time execution claim before calling the executor.
- `createPostgresExecutionGateDependencies()`: PostgreSQL storage callbacks for policy snapshots, approval records, one-time claims and audit events.
- `createPostgresApprovalService()`: a durable review queue with reviewer authorization and one-time approval evidence.
- `createPostgresPolicyService()`: transactional, versioned organization policy publishing. Custom policy rules can restrict access but cannot grant `ALLOW`.
- `createPostgresAgentCredentialService()`: machine API keys whose high-entropy secrets are shown once and stored as SHA-256 hashes, with organization scopes, expiry, and revocation.

## Requirements

- Node.js 22.12+ for the repository's test/development setup.
- PostgreSQL 15+ is recommended for the included starter migration.
- A host application's actual authentication, organization membership, resource-authorization and reviewer-permission adapters.

The policy engine itself does not call any AI API and requires no model credits.

## Basic policy check

~~~ts
import { evaluateAction } from "@backstop/core";

const result = evaluateAction({
  id: crypto.randomUUID(),
  agent: "support-agent",
  actionType: "send_external",
  resource: "email/customer-export.csv",
  summary: "Send a customer export externally",
});

if (result.decision === "BLOCK") {
  throw new Error("Backstop blocked the proposed action.");
}
if (result.decision === "REQUIRE_APPROVAL") {
  // Persist the request and pause execution in your server application.
  throw new Error("An authenticated reviewer must approve this action.");
}
// Only the separately enforced server-side tool invocation may continue.
~~~

## Server-side enforcement

Import `createExecutionGate` from `@backstop/core/execution-gate` and `createPostgresExecutionGateDependencies` from `@backstop/core/postgres-adapter`. Register actual server tools; each tool's action type is fixed by the server registration, not selected by the calling agent. In the gate dependencies, connect `getRules` to trusted policy storage and `authorizeResource` to your application's real object-/tenant-level ACL. The approval and execution-claim callbacks must use durable, transactional storage.

See the repository documentation:

- [Execution-gate integration](../../docs/execution-gate.md)
- [Storage adapter contract](../../docs/storage-adapter-contract.md)
- [Machine credentials](../../docs/agent-credentials.md)
- [Architecture and trust boundaries](../../docs/architecture.md)

## Important security boundary

This package is not a complete hosted SaaS, authentication server, or independent security certification. The included Vite console remains a local browser demonstration and does not control an agent by itself. The PostgreSQL migration must be reviewed and applied to an actual database. Human policy/credential/review routes must be protected by a real sign-in/membership system, and all authorization callbacks must be implemented by the host application.

Do not use this package as the sole protection for high-impact operations without integration testing, bypass/replay testing, operational controls, and independent security review.
