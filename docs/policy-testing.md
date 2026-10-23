# Policy scenario testing

BACKSTOP includes a model-free scenario runner for checking whether a policy produces the verdict your team expects. The goal is to catch policy regressions before an agent integration is shipped.

## What it does

Each scenario supplies:
- a stable, unique ID;
- a short description of the behavior under test;
- a representative proposed action;
- the expected verdict: `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`;
- optional restrictive policy rules.

The runner evaluates every scenario and returns a report with expected and actual verdicts, pass/fail status, the evaluator's explanation, and policy version. It does not call an AI API and never executes the action.

## Example

```ts
import { runPolicyScenarios } from "@backstop/core/scenarios";
import type { PolicyScenario } from "@backstop/core/scenarios";

const scenarios: PolicyScenario[] = [
  {
    id: "support-read",
    description: "Support agents may read the help article.",
    request: {
      id: "req-1",
      agent: "support-agent",
      actionType: "read_resource",
      resource: "help/article.md",
      summary: "Read a public help article",
    },
    expected: "ALLOW",
  },
  {
    id: "support-delete",
    description: "Destructive deletion must remain blocked.",
    request: {
      id: "req-2",
      agent: "support-agent",
      actionType: "delete_resource",
      resource: "customers/123",
      summary: "Delete a customer record",
    },
    expected: "BLOCK",
  },
];

const report = runPolicyScenarios(scenarios);
if (report.failed > 0) {
  throw new Error(`Policy regression: ${report.failed} scenario(s) failed`);
}
```

## Honest limitations

This runner tests BACKSTOP's evaluator against declared examples. It does not prove that a real agent cannot bypass the evaluator, that a resource name is truthful, or that an execution adapter enforces the verdict. Those need separate integration, adversarial, identity, and replay tests at the actual side-effect boundary. A green scenario report is useful evidence, not a security certification.
