# BACKSTOP

**Policy enforcement and regression testing for AI agent actions.**

Backstop evaluates proposed tool actions before an application executes them. The deterministic TypeScript engine returns **ALLOW**, **BLOCK**, or **REQUIRE_APPROVAL** with an explanation and matching policy. Its scenario runner lets developers check expected decisions before shipping policy changes.

## Included in this release

- Provider-independent policy engine with deterministic decisions.
- Fail-safe handling for incomplete or unknown actions.
- Locked baseline blocks for destructive deletion and money transfers.
- Restrictive custom rules, a local approval queue, request filters, audit timeline, and JSON export.
- **Model-free policy scenario runner** with machine-readable pass/fail reports for regression checks.
- Responsive local developer console, unit tests, and CI.
- No AI API, paid credits, database, or account required for the local console or policy scenario runner.

## Important boundary

This is a **local development console and policy library, not yet a hosted multi-user enforcement service**. Requests, rules, approval decisions, and audit entries in the browser live in that browser profile and can be modified by its owner. Backstop does not control another AI agent or execute real operations. Do not use the console as a production security boundary.

Production enforcement requires an authenticated server-side execution gate, trusted agent identity, persisted and authenticated approvals, organization isolation, replay/idempotency protections, trusted audit storage, integration tests, and independent security review. The policy engine and scenario runner are components, not a claim of complete agent security.

## Run locally

Requirements: Node.js 20+ and npm.

    npm install
    npm run dev

Run validation:

    npm test
    npm run check
    npm run build

## Test policy changes

Import the scenario runner from `@backstop/core/scenarios` to define actions and expected decisions in code. It reports unexpected decisions as failures, includes the reason and policy version, and makes no AI API calls.

See [Policy scenario testing](docs/policy-testing.md) for a complete example.

## Integration pattern

Evaluate immediately before executing a tool. This is an example pattern, not a complete production adapter:

    import { evaluateAction } from "@backstop/core";

    const result = evaluateAction({
      id: crypto.randomUUID(),
      agent: "support-agent",
      actionType: "send_external",
      resource: "email/customer-export.csv",
      summary: "Send an export to an external recipient"
    });

    if (result.decision === "BLOCK") throw new Error("Blocked");
    if (result.decision === "REQUIRE_APPROVAL") {
      // Persist request and pause until an authenticated reviewer decides.
      throw new Error("Human approval is required");
    }

    // Only ALLOW may reach the separately implemented tool call.

The server must independently authenticate the agent, validate the resource and exact operation, and enforce the decision before any side effect. Do not accept a UI click as proof of authorization.

## Design principles

1. Policy before side effects.
2. Unknown actions default to review.
3. Custom rules may restrict access; they cannot grant permissions.
4. Explain decisions and identify the matching policy.
5. Treat local logs as development evidence, not tamper-proof compliance records.
6. Test expected policy outcomes before integrating with real tools.

## Roadmap

- [x] Deterministic TypeScript core
- [x] Local browser console and review workflow
- [x] Restrictive rules and local audit export
- [x] Model-free policy scenario runner and regression tests
- [x] Unit tests and CI workflow
- [ ] Server-side enforcement API and tool adapters
- [ ] Authenticated users, agent identities, and tenant isolation
- [ ] Database-backed approvals and integrity-protected audit events
- [ ] Bypass, replay, and integration tests
- [ ] Independent security review

BACKSTOP is early-stage software. The agent-governance space already has capable projects, so the long-term opportunity must be earned through a specific user problem, reliable integrations, and reproducible tests—not claims about what the product might become.
