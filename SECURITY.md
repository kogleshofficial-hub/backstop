# Security policy

BACKSTOP is early-stage security-related software. Do not rely on the local browser console or these components as the sole protection for production systems, personal data, money, or critical infrastructure.

## Reporting a vulnerability

Do not publish credentials, personal data, customer payloads, or a working exploit against a live system in a public issue. Use GitHub's private vulnerability reporting feature if it is enabled. Otherwise, contact the repository maintainer privately before sharing details. Include affected commit/version, impact, safe reproduction steps, and logs with secrets removed.

## What is implemented

The repository contains a deterministic policy engine, a server-side execution-gate component, a PostgreSQL adapter for versioned policies and approval queue, atomically consumed approval evidence, unique execution claims, audit insertions, and scoped/expiring machine credentials stored as SHA-256 digests. Unit tests and CI exercise these components with test fixtures.

These are building blocks, not a complete hosted service. The browser console's rules, reviews and audit entries are local and user-editable. It is not connected to the PostgreSQL adapter. The repository does not yet provide a hosted multi-tenant API, a human sign-in/session provider, production administrator/reviewer HTTP routes, deployed database, real application-specific ACL, operational monitoring, or an independent security assessment.

## Mandatory deployment controls

Before using this to guard real operations, the deploying application must:

- Authenticate every human and machine caller over TLS, and derive user, organization, reviewer and agent permissions from trusted server-side identity/membership.
- Restrict every policy, credential, and approval management API to the right organization administrators/reviewers.
- Implement object-level authorization and verify the actual resource at the executor boundary.
- Apply the SQL migration via an owner/migration role and run the application under least-privilege database credentials. Application roles must not own the audit table or be able to update/delete/truncate its events.
- Keep database credentials and machine secrets in server-side secret management. Never expose secrets in browser code, logs, GitHub issues or client responses.
- Add rate limits, request-size limits, key rotation, expiry/revocation handling, safe error reporting, backup/recovery, operational logging/metrics/alerts and an incident process.
- Run real PostgreSQL integration tests, parallel approval-consumption/claim tests, request replay and crash-recovery tests, direct-tool bypass tests, tenant-isolation tests, and dependency/security scans.
- Arrange an independent security review before relying on the gate for high-impact operations.

The unique execution claim deliberately refuses automatic retries after an ambiguous result. Recovery should inspect the audit and real tool state instead of deleting a claim to force a retry.

## Supported security contact

Use the repository's private vulnerability reporting feature when enabled. Please do not send secrets through public GitHub issues.
