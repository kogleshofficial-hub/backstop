import { describe, expect, it } from "vitest";
import { createRestriction, DEFAULT_RULES, evaluateAction, resolveApproval, type ActionRequest, type PolicyRule } from "./index";

function request(overrides: Partial<ActionRequest> = {}): ActionRequest {
  return { id: "req-test", agent: "test-agent", actionType: "read_resource", resource: "workspace/report.md", summary: "Read a report", ...overrides };
}
describe("policy evaluation", () => {
  it("allows read-only baseline actions", () => { expect(evaluateAction(request()).decision).toBe("ALLOW"); });
  it("allows searches", () => { expect(evaluateAction(request({ actionType: "search" })).decision).toBe("ALLOW"); });
  it("requires review for writes, external sends, code, publication and permissions", () => {
    for (const actionType of ["write_resource", "send_external", "execute_code", "publish", "change_permissions"] as const) {
      expect(evaluateAction(request({ actionType })).decision).toBe("REQUIRE_APPROVAL");
    }
  });
  it("blocks destructive deletion and money movement", () => {
    expect(evaluateAction(request({ actionType: "delete_resource" })).decision).toBe("BLOCK");
    expect(evaluateAction(request({ actionType: "transfer_funds" })).decision).toBe("BLOCK");
  });
  it("defaults malformed or unknown requests to review", () => {
    expect(evaluateAction(request({ agent: " " })).decision).toBe("REQUIRE_APPROVAL");
    expect(evaluateAction(request({ id: " " })).decision).toBe("REQUIRE_APPROVAL");
    expect(evaluateAction(request({ actionType: "new_action" as ActionRequest["actionType"] })).decision).toBe("REQUIRE_APPROVAL");
  });
  it("matches resource subtree restrictions", () => {
    const rule = createRestriction({ id: "r1", name: "Block payroll", description: "Payroll requires separate access.", effect: "BLOCK", actionType: "read_resource", resourcePattern: "finance/payroll/**" });
    expect(evaluateAction(request({ resource: "finance/payroll/june.csv" }), [rule]).decision).toBe("BLOCK");
    expect(evaluateAction(request({ resource: "finance/public/june.csv" }), [rule]).decision).toBe("ALLOW");
  });
  it("custom rules cannot override locked baseline hard-blocks", () => {
    const allowDelete = { ...DEFAULT_RULES[2], id: "bad-allow", actionTypes: ["delete_resource"] as const, effect: "ALLOW" as const, locked: false };
    expect(evaluateAction(request({ actionType: "delete_resource" }), [allowDelete]).decision).toBe("BLOCK");
  });
  it("fails closed when custom policy configuration is malformed", () => {
    expect(evaluateAction(request({ actionType: "write_resource" }), [null as unknown as PolicyRule]).decision).toBe("REQUIRE_APPROVAL");
    expect(evaluateAction(request({ actionType: "write_resource" }), null as unknown as PolicyRule[]).decision).toBe("REQUIRE_APPROVAL");
  });
  it("rejects custom rules that attempt to grant permissions", () => {
    const allowRead = { ...DEFAULT_RULES[2], id: "custom-allow", locked: false };
    expect(evaluateAction(request(), [allowRead]).decision).toBe("REQUIRE_APPROVAL");
  });
  it("returns human-readable reason and policy version", () => {
    const result = evaluateAction(request({ actionType: "write_resource" }));
    expect(result.reason).toContain("reviewer");
    expect(result.policyVersion).toBe("backstop-baseline-1.0.1");
  });
});
describe("approval resolution", () => {
  it("records reviewer evidence", () => {
    const result = resolveApproval({ id: "req1", status: "pending" as const }, "approve", "operator", "2026-10-22T00:00:00.000Z");
    expect(result.status).toBe("approved");
    expect(result.reviewer).toBe("operator");
    expect(result.reviewedAt).toBe("2026-10-22T00:00:00.000Z");
  });
  it("rejects a second resolution", () => {
    expect(() => resolveApproval({ id: "req1", status: "approved" as const }, "reject", "operator")).toThrow("Only pending requests can be resolved.");
  });
  it("requires a reviewer identity", () => {
    expect(() => resolveApproval({ id: "req1", status: "pending" as const }, "approve", " ")).toThrow("A reviewer identity is required.");
  });
});
describe("restriction creation", () => {
  it("cannot be used to grant permissions", () => {
    expect(() => createRestriction({ id: "r1", name: "Denied", description: "No", effect: "ALLOW" as "BLOCK", actionType: "read_resource", resourcePattern: "*" })).toThrow();
  });
  it("rejects empty rule details", () => {
    expect(() => createRestriction({ id: "r1", name: "", description: "Reason", effect: "BLOCK", actionType: "read_resource", resourcePattern: "*" })).toThrow();
  });
  it("requires a rule id and known action type", () => {
    expect(() => createRestriction({ id: " ", name: "Denied", description: "Reason", effect: "BLOCK", actionType: "read_resource", resourcePattern: "*" })).toThrow();
    expect(() => createRestriction({ id: "r2", name: "Denied", description: "Reason", effect: "BLOCK", actionType: "unknown" as ActionRequest["actionType"], resourcePattern: "*" })).toThrow();
  });
});
