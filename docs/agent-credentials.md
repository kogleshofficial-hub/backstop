# Agent API credentials

BACKSTOP provides a PostgreSQL-backed machine credential service for server-to-server agents. It is not a login/session provider for people; use your web application's normal authenticated session and organization membership checks for human management routes.

## Credential behavior

- Secrets use the `bsk_live_` prefix plus 256 bits of cryptographically random material.
- Only the SHA-256 digest is stored in PostgreSQL. The secret is returned once by `create()`; copy it into a protected secret manager at creation time. It cannot be retrieved later.
- Each credential belongs to one organization and agent identity, has a server-defined action allowlist, and expires. The default lifetime is 90 days; configured lifetimes are limited to one hour through one year.
- The management service can list metadata and revoke a key. Revoked, expired, malformed, or unknown tokens authenticate to `null`.
- Creation/revocation events are written to the audit table in the same transaction as the credential change.

## Example

```ts
import { Pool } from "pg";
import { createPostgresAgentCredentialService } from "@backstop/core/postgres-adapter";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const credentials = createPostgresAgentCredentialService(pool, {
  // This callback must use trusted session/membership data, not user-supplied body fields.
  authorizeCredentialManagement: ({ organizationId, actorId }) =>
    membershipStore.canManageAgentCredentials(organizationId, actorId),
});

// In an authenticated organization-admin route:
const result = await credentials.create({
  organizationId: session.organizationId,
  actorId: session.userId,
  agentId: validatedAgent.id,
  allowedActions: ["read_resource", "search"],
  ttlSeconds: 60 * 60 * 24 * 30,
});

// Display result.secret ONCE. Never log it or send it in normal API responses.
return { credentialId: result.credentialId, keyPrefix: result.keyPrefix, secret: result.secret };

// In middleware for a machine-to-machine route:
const authenticated = await credentials.authenticate(request.headers.get("authorization")?.replace(/^Bearer /i, "") ?? "");
if (!authenticated) throw new Error("Unauthorized");
// Pass authenticated.agent into the execution gate. Do not accept agent IDs or scopes from body JSON.

// In a protected admin route:
const metadata = await credentials.list({
  organizationId: session.organizationId,
  actorId: session.userId,
});
await credentials.revoke({
  organizationId: session.organizationId,
  actorId: session.userId,
  credentialId: metadata[0].credentialId,
});
```

The example's `session`, `membershipStore`, `validatedAgent`, and route handler are host-app concepts; BACKSTOP does not implement those for you. Derive the organization and actor from trusted authentication state, and validate the agent ID/action scopes before calling the service.

## Migration and operations

Apply `packages/core/migrations/001_execution_control.sql` to the real PostgreSQL database using a migration owner. Restrict the runtime role to the required credential SELECT/INSERT/UPDATE permissions and audit INSERT permission. Do not grant users direct table access. The table stores hashes, not secret tokens.

Set up rotation by creating a new key, installing it in the protected agent environment, verifying the new key works, then revoking the old key. Keep expiration monitoring and a recovery process. Never expose raw keys in logs, browser storage, issue reports, screenshots, or analytics.

## Security limits

The credential service authenticates bearer secrets but does not itself implement human login, role management, MFA, network restrictions, rate limits, request signatures, bot detection, or secret-manager integration. The HTTP application must enforce TLS, rate limiting, request-size limits, organization isolation, and permission checks. Treat a credential as a secret: anyone who obtains it can act within its granted scope until it expires or is revoked.
