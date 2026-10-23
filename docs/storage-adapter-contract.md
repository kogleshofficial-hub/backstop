# Persistent storage adapter contract

This guide defines the minimum behavior expected from the callbacks injected into BACKSTOP's execution gate. The schema in `packages/core/migrations/001_execution_control.sql` is a starting point, not a ready-to-deploy database service.

## Required operations

**Load policy.** Fetch only the current rules for the authenticated agent's organization, and validate the policy version and every rule before evaluation. Do not let browser-submitted rules override stored policy.

**Record an approval request.** Insert the action metadata and its SHA-256 input digest keyed by `(organization_id, request_id)`. If the row already exists with the same digest and is still pending, handling may be idempotent. If the digest or operation differs, refuse it. Set a finite expiry. Store no raw tool secrets in the audit summary.

**Verify and consume approval.** In one database transaction, lock the approval row, confirm the organization, request ID, tool/action, resource, payload digest, pending/approved status, expiry, and reviewer authorization; then change it to consumed. Exactly one concurrent call may succeed. The gate will not run the tool unless the callback returns true.

**Claim execution.** Atomically insert into `backstop_execution_claims` with a unique `(organization_id, request_id)` key, binding the row to the request's input digest. Return true only when this call inserted the first claim. A conflicting row must return false. Never delete the row simply to make a retry succeed without investigating whether the operation already took effect.

A simple PostgreSQL claim pattern is:

```sql
INSERT INTO backstop_execution_claims
  (organization_id, request_id, agent_id, tool_name, action_type, resource, input_digest)
VALUES
  ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (organization_id, request_id) DO NOTHING
RETURNING request_id;
```

Return true only if one row was returned. The application must handle a conflict as a refused replay; comparing just the request ID is insufficient for approval binding, so also store and validate `input_digest`.

**Append audit.** Insert server-generated timestamps and all event fields into an append-only audit table. Give the runtime database role the minimum grants needed to insert and read records; do not grant it update/delete/truncate of audit rows. Restrict who can query audit events containing resource identifiers.

## Operational truth

The schema does not create its own database, users, authentication, secrets, network security, tenant permissions, approval interface, or monitoring. The integration must be implemented and tested with the chosen database and hosting platform. This repository does not yet provide a real connected production deployment.
