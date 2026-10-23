# Architecture and trust boundaries

BACKSTOP has two separate surfaces: a local browser console for experimenting with policies, and server-side TypeScript components that applications can embed before their AI agent invokes real tools.

## Components

1. **Policy evaluator** — deterministic, model-free TypeScript. It returns `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. Incomplete and unknown operations default to review. Locked baseline prohibitions block destructive deletion and money transfers. Invalid custom policy configuration blocks rather than silently granting access.
2. **Execution gate** — wraps server-registered tool definitions with fixed action types. It snapshots JSON input, computes a SHA-256 digest, checks the authenticated agent's action scope and the host application's resource ACL, loads an organization policy snapshot, records a trusted audit event before execution, atomically claims the request ID, and then calls the registered executor. Review-gated actions are not executed until approval is durably recorded, authenticated, verified against the same request and payload, and atomically consumed.
3. **PostgreSQL adapter** — loads versioned organization policies from a single-statement snapshot; transactionally publishes custom restrictive rules; persists approval requests and reviewer decisions; consumes approval evidence once; claims each organization/request pair once; inserts audit events; and manages expiring organization-scoped machine API keys whose secrets are stored as hashes.
4. **Browser console** — provides example requests, policy editing, a local review flow, and a local audit timeline. Its browser storage is controlled by that browser profile; it is **not** connected to a production database and is not a production security boundary.

## Request path

1. The host application's authentication middleware authenticates the caller. It constructs the `AuthenticatedAgent` from trusted server-side identity/membership data, or obtains one from a validated machine credential. Never trust agent, organization, or permission fields in the client JSON body.
2. A registered server tool validates input and describes the exact resource and a non-sensitive summary. The action type is fixed by the server registration.
3. The gate computes the digest of the canonical JSON input, verifies the action scope and app-level object/organization ACL, and loads a consistent versioned policy snapshot.
4. A deny decision is audited and stops execution. A review decision is saved to the persistent approval queue. A reviewer route must authenticate the reviewer, check organization membership and permission, then atomically approve or reject the pending row.
5. For approved actions, the gate verifies and consumes approval evidence bound to the organization, agent, tool, action type, resource, summary, request ID, policy revision, and input digest.
6. Immediately before executing an allowed tool, the gate must write a pre-execution audit event and acquire a durable unique claim for that organization/request ID. A repeated/conflicting ID or any pre-execution storage error refuses to execute.
7. The registered executor performs the operation using least-privilege server-side credentials. The gate attempts to record success/failure afterward. If post-execution audit fails, the operation might already have happened; the result marks audit as incomplete and operators must investigate before manual recovery.

## Persistent storage

The starter schema is `packages/core/migrations/001_execution_control.sql`. It includes versioned policy data, approval records, agent credentials, unique execution claims, and audit events. The runtime should use a restricted DB role; schema ownership belongs to the migration role. In particular, application roles must not own or update/delete/truncate audit records.

The adapter exposes database calls but does not provision PostgreSQL, configure TLS/networking, manage credentials in an external secret manager, or verify a real DB server in this repository. Apply the migration to a real database and test the adapter against that real service before use.

## Trust assumptions and limitations

- Resource ACL callbacks must check access to the actual resource and organization, not just trust its name from an agent proposal.
- `authorizeReviewer` and the policy/credential-management callbacks must check trusted server-side membership and the requested organization.
- The `claimExecution` adapter uses a unique organization/request key, conservatively refusing replay. If a process crashes after the claim but before the tool result is durably known, BACKSTOP intentionally does not automatically retry. A controlled recovery process must inspect logs and external side effects.
- Audit append is application/database controlled, not cryptographically tamper-proof by itself. Harden retention, access, backups, and alerting.
- API credentials are bearer secrets. They need TLS, rate limiting, protected admin routes, rotation and revocation; a token should be limited to the minimum action scopes.
- The local console's approval buttons are demonstrations only. They do not create trusted approvals for the execution gate.
- Unit tests use a fake SQL harness. They do not substitute for integration tests with PostgreSQL, real auth/ACL services, registered tools, parallel requests, real transaction isolation, crash recovery and adversarial bypass attempts.

## Before production

Configure and verify actual authenticated routes; provision and secure PostgreSQL; apply and rehearse migrations/backups; create restricted database grants; implement and test the host's object-level ACL; expose approval, policy and credential management only through protected administrator/reviewer routes; rate-limit public endpoints; add logs, metrics and alerts; review dependency advisories; run concurrency, replay, bypass and tenant-isolation tests; and obtain independent security review.

This architecture is a set of reusable security components, not a claim of complete agent security or a certification.
