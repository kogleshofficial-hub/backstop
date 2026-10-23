import { describe, expect, it } from "vitest";
import { runPolicyScenarios } from "./scenarios.js";
import { POLICY_VERSION, type ActionRequest } from "./index.js";

function request(overrides: Partial<ActionRequest> = {}): ActionRequest {
  return {
    id: "scenario-request",
    agent: "test-agent",
    actionType: "read_resource",
    resource: "workspace/report.md",
    summary: "Read a report",
    ...overrides,
  };
}

describe("policy scenario runner", () => {
  it("returns a machine-readable report for expected policy outcomes", () => {
    const report = runPolicyScenarios([
      {
        id: "read-is-allowed",
        description: "Read-only access matches the baseline.",
        request: request(),
        expected: "ALLOW",
      },
      {
        id: "deletion-is-blocked",
        description: "Destructive deletion cannot be allowed by custom rules.",
        request: request({ actionType: "delete_resource" }),
        expected: "BLOCK",
      },
      {
        id: "external-send-needs-review",
        description: "External sends pause for review.",
        request: request({ actionType: "send_external" }),
        expected: "REQUIRE_APPROVAL",
      },
    ]);

    expect(report.total).toBe(3);
    expect(report.passed).toBe(3);
    expect(report.failed).toBe(0);
    expect(report.results.every((result) => result.passed)).toBe(true);
    expect(report.policyVersion).toBe(POLICY_VERSION);
  });

  it("marks an unexpected decision as a failed scenario instead of hiding it", () => {
    const report = runPolicyScenarios([
      {
        id: "intentional-mismatch",
        description: "This scenario deliberately expects the wrong result.",
        request: request(),
        expected: "BLOCK",
      },
    ]);

    expect(report.passed).toBe(0);
    expect(report.failed).toBe(1);
    expect(report.results[0].actual).toBe("ALLOW");
    expect(report.results[0].passed).toBe(false);
  });

  it("rejects duplicate scenario IDs", () => {
    const scenario = {
      id: "same-id",
      description: "A scenario",
      request: request(),
      expected: "ALLOW" as const,
    };
    expect(() => runPolicyScenarios([scenario, scenario])).toThrow(
      "Duplicate policy scenario id: same-id",
    );
  });

  it("rejects blank IDs and descriptions", () => {
    expect(() =>
      runPolicyScenarios([
        { id: " ", description: "A scenario", request: request(), expected: "ALLOW" },
      ]),
    ).toThrow("Every policy scenario needs a non-empty id.");

    expect(() =>
      runPolicyScenarios([
        { id: "scenario", description: " ", request: request(), expected: "ALLOW" },
      ]),
    ).toThrow("Scenario scenario needs a description.");
  });
});
