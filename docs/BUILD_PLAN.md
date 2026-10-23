# BACKSTOP Build Plan

This file tracks the path from a local developer console to a reliable product.

## Current release
- Deterministic TypeScript policy engine.
- Browser-based local console.
- Local review queue and local event history.
- Automated unit tests and continuous integration.

## Next milestones
1. Write down the supported use case and the exact limits of the first integration.
2. Build a server-side API that owns policy evaluation and request state.
3. Add authenticated identities and persistent server-side approvals.
4. Add one real tool integration and tests proving requests pass through the server.
5. Add operational monitoring, recovery procedures, and an external security review.

## Release rule
A feature is not complete because it appears in the interface. It is complete when its behavior is implemented, tested, documented, and its limitations are clear.

## Cost rule
Keep the policy engine deterministic and free of paid AI inference. Use free local development tools where practical. Revisit hosting costs only after the first integration is working and tested.
