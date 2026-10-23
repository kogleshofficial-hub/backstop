import {
  evaluateAction,
  POLICY_VERSION,
  type ActionRequest,
  type Decision,
  type PolicyRule,
} from "./index.js";

/**
 * A reproducible, model-free check of a policy against an expected verdict.
 * This reports a decision only; it never executes the requested operation.
 */
export interface PolicyScenario {
  id: string;
  description: string;
  request: ActionRequest;
  expected: Decision;
  rules?: readonly PolicyRule[];
}

export interface PolicyScenarioResult {
  id: string;
  description: string;
  expected: Decision;
  actual: Decision;
  passed: boolean;
  reason: string;
  policyVersion: string;
}

export interface PolicyScenarioReport {
  total: number;
  passed: number;
  failed: number;
  policyVersion: string;
  results: PolicyScenarioResult[];
}

export function runPolicyScenarios(
  scenarios: readonly PolicyScenario[],
): PolicyScenarioReport {
  const seen = new Set<string>();

  for (const scenario of scenarios) {
    if (!scenario.id.trim()) {
      throw new Error("Every policy scenario needs a non-empty id.");
    }
    if (seen.has(scenario.id)) {
      throw new Error(`Duplicate policy scenario id: ${scenario.id}`);
    }
    if (!scenario.description.trim()) {
      throw new Error(`Scenario ${scenario.id} needs a description.`);
    }
    seen.add(scenario.id);
  }

  const results = scenarios.map((scenario): PolicyScenarioResult => {
    const evaluation = evaluateAction(scenario.request, scenario.rules);
    return {
      id: scenario.id,
      description: scenario.description,
      expected: scenario.expected,
      actual: evaluation.decision,
      passed: evaluation.decision === scenario.expected,
      reason: evaluation.reason,
      policyVersion: evaluation.policyVersion,
    };
  });

  const passed = results.filter((result) => result.passed).length;
  return {
    total: results.length,
    passed,
    failed: results.length - passed,
    policyVersion: POLICY_VERSION,
    results,
  };
}
