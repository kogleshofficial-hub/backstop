# BACKSTOP

**The policy gate between an AI agent and the actions it wants to take.**

Backstop evaluates proposed tool actions before an application executes them. The deterministic TypeScript engine returns **ALLOW**, **BLOCK**, or **REQUIRE_APPROVAL** with an explanation and matching policy.

## Included in this release

- Provider-independent policy engine with deterministic decisions.
- Fail-safe handling for incomplete or unknown actions.
- Locked baseline blocks for destructive deletion and money transfers.
- Restrictive custom rules, a local approval queue, request filters, audit timeline, and JSON export.
- Responsive local developer console, unit tests, and CI.
- No AI API, paid credits, database, or account required for the local console.

## Important boundary

This is a **local development console, not yet a hosted multi-user enforcement service**. Requests, rules, approval decisions, and audit entries live in this browser profile and can be modified by its owner. Backstop does not control another AI agent or execute real operations. Do not use the console as a production security boundary.

Production enforcement requires an authenticated server-side execution gate, trusted agent identity, persisted and authenticated approvals, organization isolation, replay/idempotency protections, trusted audit storage, integration tests, and independent security review. The policy engine is a starting component, not a claim of complete agent security.

## Run locally

Requirements: Node.js 20+ and npm.

    npm install
    npm run dev

Run validation:

    npm test
    npm run check
    npm run build

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

## Roadmap

- [x] Deterministic TypeScript core
- [x] Local browser console and review workflow
- [x] Restrictive rules and local audit export
- [x] Unit tests and CI workflow
- [ ] Server-side enforcement API and tool adapters
- [ ] Authenticated users, agent identities, and tenant isolation
- [ ] Database-backed approvals and integrity-protected audit events
- [ ] Bypass, replay, and integration tests
- [ ] Independent security review

BACKSTOP is early-stage software. Specific integrations, threat models, and reproducible test cases matter more than claims about what the product might become.
