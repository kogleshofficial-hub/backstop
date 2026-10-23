# BACKSTOP

**Policy enforcement and testing for AI agent actions.**

BACKSTOP provides a deterministic TypeScript policy engine and an embeddable server-side execution gate. It evaluates proposed tool actions as **ALLOW**, **BLOCK**, or **REQUIRE_APPROVAL** before the registered operation can run.

## What is in this repository

- Deterministic policy engine with restrictive custom rules and locked baseline blocks.
- Fail-closed handling of malformed requests and invalid custom policy configuration.
- Model-free policy scenario runner for regression checks.
- Server-side execution-gate library that binds fixed tool definitions to action types, checks the authenticated agent's action allowlist and resource authorization, verifies approval evidence for review-gated actions, and refuses execution when pre-execution audit storage fails.
- Local browser console for exploring requests and policies.
- Unit tests and GitHub Actions CI.
- No AI API or paid model credits required.

## Start locally

Requirements: Node.js 22.12+ and npm.

```sh
npm install
npm run dev
```

Open the local URL printed by Vite. Run the tests and build checks with:

```sh
npm test
npm run check
npm run build
npm audit --audit-level=high
```

## Server-side execution gate

Import the gate from `@backstop/core/execution-gate` and register your application's actual server-side tools. Each tool definition fixes its action type and derives its target resource from validated input. The gate checks that request against policies and the application's resource authorization adapter before invoking the registered executor.

Read [the execution-gate integration guide](docs/execution-gate.md) and [policy scenario testing guide](docs/policy-testing.md) before integrating it.

## Security boundary — read before use

The browser console is a local development interface. Its browser-held requests, rules, approvals, and events are not trusted production records, and it cannot protect an agent by itself.

The execution-gate module is an integration component, not a complete hosted security product. It depends on the host application's trusted authentication, durable policy and approval stores, object-level access control, audit storage, and correct tool adapters. Approval verification must bind the approval to the exact operation, request, organization, resource, and input digest, and must prevent replay. Tool adapters must use server-side credentials with least privilege. Do not use this repository as the sole security boundary for money, critical infrastructure, or sensitive production data; independent security review is required before production reliance.

See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting and the current boundary.

## Project direction

The long-term product goal is infrastructure developers can embed between an AI agent and any real tool it can invoke. A generic policy dashboard alone is not enough to differentiate this product. The next priorities are concrete adapters, persistent approval workflow, authenticated agent and organization identities, tamper-evident audit storage, idempotency/replay protection, adversarial integration tests, and customer validation.

BACKSTOP is early-stage software. It makes no claim that an agent can never bypass its controls or that any security certification has been achieved.
