# Contributing

BACKSTOP is early-stage infrastructure software. Security boundaries and failure behavior take precedence over new features.

## Local development

Requirements: Node.js 22.12+ and npm.

~~~sh
npm install
npm run dev
~~~

Before submitting a change, run:

~~~sh
npm test
npm run check
npm run build
npm audit --audit-level=high
~~~

## Security-sensitive changes

Changes involving policy precedence, authentication, approval verification, tool registration, resource authorization, database transactions, credentials, replay handling or audit events require tests covering both the expected action and the failure path. Keep the policy engine deterministic and model-free. Do not make network/model decisions inside the critical policy evaluator.

Never commit real API keys, database connection strings, customer payloads, screenshots containing secrets, or production audit records. Use synthetic identities and resources in unit tests.

## Design constraints

- Custom organization rules may BLOCK or REQUIRE_APPROVAL; they may not grant permissions.
- Unknown actions fail closed.
- Human approval must be bound to the organization, request, tool, operation, target and exact canonical input digest.
- Execution claims and approval consumption must be atomic in durable storage.
- A browser event is not proof of authorization.
- Audit storage must be controlled by the server; the runtime role should not be able to rewrite historical events.
- Document all assumptions that depend on the host application's authentication and resource ACL callbacks.

Do not claim certification or production readiness without independent evidence. See the architecture guide, SECURITY.md, and launch-readiness checklist.
