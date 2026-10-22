# Architecture and trust boundaries

The core policy evaluator is a pure TypeScript module. It does not call a model, make network requests, or execute operations. The browser UI submits proposals, displays explanations, lets users create restrictive rules, and records local decisions in browser storage.

Decision flow:

1. Normalize the proposed action using an authenticated agent identity, type, target resource, and summary.
2. Incomplete or unknown requests return REQUIRE_APPROVAL.
3. Locked baseline rules BLOCK destructive deletion and funds transfer before custom rules are considered.
4. Otherwise, enabled rules match action type and resource pattern. The strongest decision wins: BLOCK, then REQUIRE_APPROVAL, then ALLOW.
5. A request with no matching rule defaults to REQUIRE_APPROVAL.
6. The actual server-side caller must enforce the decision before any side effect.

The browser console has no accounts, tenant isolation, trusted server authorization, agent credentials, persistent approval API, immutable logs, policy signatures, or execution adapters. Its audit data is user-editable and must not be used as a production compliance record.

Before production, add:
- user, organization, and agent identity with least-privilege authorization;
- a server-side gate around the exact tool invocation;
- database-backed approvals, expiry, idempotency and replay protection;
- server-owned append-only audit storage and policy version control;
- rate limits, monitoring, secrets handling and bypass tests;
- independent security review.
