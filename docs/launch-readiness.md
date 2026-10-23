# Launch readiness

This document separates implemented software from prerequisites that still require an actual deployment and real-system testing.

## Implemented in the repository

- [x] Deterministic policy evaluator and model-free test runner.
- [x] Fail-closed behavior for malformed requests and invalid custom policy configuration.
- [x] Server-side tool execution gate with fixed registered action types, canonical input digest, caller action scope, resource ACL callback and versioned organization policy snapshot.
- [x] PostgreSQL adapter for versioned policy publishing, durable approval queue, reviewer decisions, one-time approval consumption, unique execution claims, audit inserts, and scoped/expiring machine credentials stored as hashes.
- [x] Starter PostgreSQL migration.
- [x] Unit tests for policy decisions, approval workflow, policy publishing, credentials and adapter behavior.
- [x] CI checks for tests, type/build validation, and high-severity dependency advisories.
- [x] Documentation of trust boundaries and responsible vulnerability reporting.

## Required before a real customer can rely on it

- [ ] Deploy the application with a working server runtime; the current browser console still uses local browser storage and is not wired to the PostgreSQL service.
- [ ] Provision PostgreSQL, apply/review the migration, define a restricted runtime role and test backups, restores and upgrades.
- [ ] Implement real human sign-in/session management, organization memberships, protected policy/credential/approval routes, and reviewer MFA as appropriate.
- [ ] Connect authorizeResource, authorizeReviewer, authorizePolicyManagement, and authorizeCredentialManagement to real authorization systems. Test cross-organization denial.
- [ ] Register and test concrete tools that operate on real resources; prove each executor uses the same verified resource that BACKSTOP evaluated.
- [ ] Add rate limiting, request-size limits, secret management/rotation, telemetry, alerting, security-event handling and audit retention controls.
- [ ] Run real PostgreSQL integration tests, concurrent approval/claim tests, failure injection, agent bypass/replay tests, and tenant-isolation tests.
- [ ] Obtain independent security review before use for high-impact actions.
- [ ] Validate the market with developers and teams that have the problem, and prove that BACKSTOP is measurably better than their current controls.

## Release rule

Do not call the application production-ready simply because unit tests pass. A CI-green commit shows that repository checks pass; it does not prove that deployment configuration, identity systems, database permissions, real tool adapters or operational security are correct.

## Current deployment status

The GitHub repository and code are available. No live PostgreSQL database has been provisioned or connected by this project, and a Vercel project could not be created with the available account permissions. The current console should be described as a local development interface until a working, authorized deployment is configured and verified.
