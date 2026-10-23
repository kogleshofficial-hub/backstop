# BACKSTOP Threat Model

**Status:** Initial working document — must be reviewed and updated alongside implementation.

## 1. Security objective

BACKSTOP aims to make a policy decision immediately before an AI agent's proposed tool operation can cause a side effect. The intended decisions are:

- **ALLOW** — the operation may continue only if the enforcement service has independently validated the request and the caller's authorization.
- **REQUIRE_APPROVAL** — execution must pause until an authenticated, authorized reviewer approves the exact operation.
- **BLOCK** — the operation must not execute.

The decision engine is one control in a larger system. It cannot determine every harmful or incorrect intent from a summary string.

## 2. Assets to protect

- Customer systems and data reached by connected agents.
- Credentials and identity material used by agents and integrations.
- Policy definitions and locked baseline rules.
- Approval decisions and reviewer identities.
- Audit records needed to investigate incidents.
- Availability and integrity of the enforcement service.

## 3. Trust boundaries

1. **Untrusted agent request → enforcement API.** All request fields must be treated as untrusted input.
2. **Enforcement API → policy engine.** Only validated, versioned request shapes and server-loaded policy may cross this boundary.
3. **Approval interface → approval service.** A browser event is not proof of reviewer identity or authorization.
4. **Enforcement service → downstream tool.** A decision must be bound to the exact operation, target, and request identifier that will execute.
5. **Service → audit storage.** Audit writes must not be silently skipped on a security-relevant decision.
6. **Tenant → tenant.** Identity, policies, approvals, and records must be isolated by tenant on the server.

The current repository does **not** implement all of these boundaries. Its browser console stores data locally and must be treated as a development interface only.

## 4. Threats and required controls

| Threat | Required control before production |
| --- | --- |
| Agent bypasses the policy gate | Give the agent only gateway credentials; deny direct downstream credentials and network paths where feasible; test bypass attempts |
| Forged or replayed request | Authenticate the caller, validate request schema, bind decisions to a nonce/idempotency key and exact operation, enforce expiry |
| Approval spoofing or time-of-check/time-of-use change | Authenticate reviewers server-side; authorize by role; approve a canonical operation hash; revalidate immediately before execution |
| Custom rule accidentally grants access | Validate rules server-side; allow custom policies only to restrict baseline behavior; immutable locked invariants; adversarial tests |
| Cross-tenant data exposure | Derive tenant from authenticated identity, never from an untrusted body field; enforce tenant scope in every query |
| Audit record altered or omitted | Server-owned append-only event interface, restricted database roles, integrity checks, backups, and monitored failures |
| Downstream operation succeeds but audit/response fails | Define transaction and retry semantics per adapter; use idempotency where supported; reconcile uncertain outcomes |
| Secret leaks in logs or browser | Keep secrets server-side; redact tokens and sensitive payloads; define retention and access controls |
| Malformed or ambiguous operation | Strict schema validation and canonical resource identifiers; fail closed on unknown action types or targets |
| Enforcement service unavailable | Fail closed for protected actions; document availability impact and provide a deliberate emergency procedure |

## 5. Out of scope for the current local console

The current local console does not protect real external systems, authenticate agents, establish tenant boundaries, provide tamper-resistant audit storage, or guarantee rollback. It cannot prevent a tool from being called directly outside the console. Browser-local logs are not compliance evidence.

## 6. Abuse and failure testing

Before any production claim, tests must include:
- Unknown actions and missing/extra fields.
- Attempts to weaken locked rules.
- Resource-prefix, case, path-normalization, and encoding edge cases.
- Approval replay, expired approval, and modified operation after approval.
- Unauthenticated and cross-tenant access attempts.
- Direct downstream access that bypasses the gateway.
- Timeouts, duplicate delivery, partial downstream failures, and audit-storage failure.
- Secret redaction and safe error responses.

## 7. Release gate

No release should be described as production-ready until a specific integration has a documented threat model, automated tests for its enforcement path, an operator runbook, safe failure behavior, backup/recovery procedures where applicable, and an independent security review. Passing unit tests alone is not sufficient.
