# Changelog

All entries describe repository changes; they do not imply a published npm release.

## Unreleased

- Added a model-free policy scenario runner and test report.
- Added a server-side registered-tool execution gate with input snapshots, digests, authorization callbacks, versioned policies, approval verification, durable execution claims, and audit events.
- Added a PostgreSQL adapter for versioned organization policies, transactional policy publishing, pending approvals, reviewer decisions, one-time approval consumption, machine credentials and audit records.
- Added a PostgreSQL migration starter for policy, approval, claims, credentials, and audit data.
- Added tests for policy, execution, approval, policy-publishing and credential behavior.
- Upgraded the test runner and made CI fail on high or critical npm audit findings.
- Improved implementation, security boundary, integration, architecture and deployment-readiness documentation.

### Not included in this release

No customer-facing multi-tenant service, hosted database, login/session provider, production HTTP routes, real application ACL, or independent security assessment has been deployed by this repository.
