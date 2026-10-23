# Production Architecture Direction

**Status:** Design target, not implemented functionality. Do not infer that the current application provides these capabilities.

## Product focus

BACKSTOP should start with one narrow promise: **a tool call cannot reach a supported downstream system unless the server-side gate has evaluated the exact operation and permitted it**. A generic dashboard alone is not the product; an enforceable boundary and a testable integration are.

The first integration should be selected based on real developer interviews and a concrete threat model. Avoid claiming support for every AI framework or tool before each adapter has its own tests.

## Intended request path

```text
AI agent
  │ authenticated request + idempotency key
  ▼
BACKSTOP gateway
  ├─ authenticate agent and derive tenant from identity
  ├─ validate and canonicalize the operation
  ├─ load a versioned server-side policy
  ├─ evaluate immutable baseline + tenant restrictions
  ├─ BLOCK ───────────────────────────────► return denial
  ├─ REQUIRE_APPROVAL ─► durable pending record; do not execute
  └─ ALLOW / approved exact operation
        ├─ revalidate identity, policy version, expiry, operation hash
        ├─ execute through the adapter using gateway-held credentials
        ├─ record outcome and audit event
        └─ return a minimal, redacted result
```

This is a design target. The current browser app is not this gateway.

## Required service boundaries

### 1. Gateway API

- Version all external API routes and request/response schemas.
- Authenticate machine callers and map identity to a server-owned tenant.
- Validate every request with a strict schema; reject unknown operation types.
- Never accept a client-supplied decision as authoritative.
- Enforce rate limits, request size limits, deadlines, and idempotency semantics.
- Keep downstream credentials out of the browser and agent prompt/context.

### 2. Policy engine

- Remain deterministic and independent of any AI model.
- Keep non-overridable baseline prohibitions in code, not tenant-editable data.
- Permit customer policy to restrict baseline permissions, never broaden them.
- Version policies and attach the version and canonical operation hash to each decision.
- Treat natural-language summaries as display-only, not as the authoritative target or operation.

### 3. Approval service

- Persist pending approvals on the server.
- Authenticate reviewers and check their role for the tenant and resource.
- Bind approval to a canonical representation/hash of the exact operation.
- Expire requests; reject duplicate, stale, or replayed decisions.
- Revalidate policy and target immediately before execution.
- Never execute merely because the UI shows an approval button was clicked.

### 4. Execution adapters

- Each adapter must own validation of its supported operation schema.
- The agent must not retain direct credentials that bypass the gateway.
- Use least-privilege downstream credentials and network controls where available.
- Document which operations are supported, unsupported, reversible, or irreversible.
- Do not promise rollback unless the downstream system and adapter prove it.

### 5. Audit and storage

- Store tenants, agents, policies, approval requests, decisions, and execution outcomes server-side.
- Scope every read/write to the authenticated tenant.
- Use migrations, backups, retention rules, and least-privilege database roles.
- Make audit events append-only at the application interface; protect integrity and alert on gaps.
- Redact secrets and avoid recording full sensitive payloads by default.

## Deployment stages

1. **Local engine:** deterministic rules, comprehensive unit tests, no side effects.
2. **One integration in a disposable environment:** prove that every supported call is routed through the gateway; test bypass and failure paths.
3. **Private alpha:** authenticated users and agents, server-side approvals, tenant isolation, durable storage, operational logs, and documented limits.
4. **External security review:** fix findings before production claims.
5. **Production release:** only after measured reliability, recovery drills, incident response, privacy/retention documentation, and explicit support policy.

## Explicit non-goals for the first release

- Universal protection against every AI-agent failure.
- Detecting intent from arbitrary natural language with perfect accuracy.
- Automatic rollback of arbitrary external actions.
- Claiming that a dashboard or local log is a security boundary.
- Adding paid AI inference just to make policy decisions. Deterministic policy evaluation should not require an AI API.

## Definition of done for a protected integration

- A documented threat model and supported-operation matrix exist.
- The agent has no usable direct path or credential to bypass the gateway under the documented deployment model.
- Tests prove that block, approval, timeout, replay, malformed input, and service outage paths do not accidentally execute protected operations.
- Approval is authenticated and bound to the exact operation.
- Audit and downstream outcome semantics are documented and tested, including partial failure.
- Secrets are redacted, tenant isolation is tested, and an operator can diagnose and recover failures.
- An independent reviewer has assessed the integration before it is described as production-ready.
