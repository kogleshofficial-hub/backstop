import { describe, expect, it, vi } from "vitest";
import { createExecutionGate, type AuthenticatedAgent, type GateAuditEvent, type GuardedActionRequest, type GuardedTool } from "./execution-gate.js";
import type { PolicyRule } from "./index.js";

interface Input { resource: string; message?: string }
const agent: AuthenticatedAgent = {
  id: "agent-1",
  organizationId: "org-1",
  allowedActions: ["read_resource", "write_resource", "delete_resource", "send_external"],
};

function makeTool(overrides: Partial<GuardedTool<Input, string>> = {}): GuardedTool<Input, string> {
  return {
    name: "documents.read",
    actionType: "read_resource",
    parseInput(input) {
      if (!input || typeof input !== "object" || typeof (input as Input).resource !== "string") {
        throw new Error("Invalid input");
      }
      return { ...(input as Input) };
    },
    describe(input) {
      return { resource: input.resource, summary: "Read a document" };
    },
    execute: vi.fn(async (input) => input.resource),
    ...overrides,
  };
}

function harness(options: {
  tool?: GuardedTool<Input, string>;
  rules?: readonly PolicyRule[];
  authorizeResource?: (args: { agent: AuthenticatedAgent; actionType: "read_resource" | "write_resource" | "delete_resource" | "send_external"; resource: string }) => Promise<boolean>;
  verifyAndConsumeApproval?: (args: { agent: AuthenticatedAgent; request: GuardedActionRequest; inputDigest: string; approval: { requestId: string; approvalId: string } }) => Promise<boolean>;
  claimExecution?: (args: { agent: AuthenticatedAgent; request: GuardedActionRequest; toolName: string }) => Promise<boolean>;
  recordApprovalRequest?: (args: { agent: AuthenticatedAgent; request: GuardedActionRequest; evaluation: { decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL"; reason: string; matchedRules: PolicyRule[]; policyVersion: string } }) => Promise<void>;
  appendAudit?: (event: GateAuditEvent) => Promise<void>;
} = {}) {
  const events: GateAuditEvent[] = [];
  const approvalRequests: GuardedActionRequest[] = [];
  const claims = new Set<string>();
  const execute = options.tool?.execute ?? vi.fn(async (input: Input) => input.resource);
  const gate = createExecutionGate([options.tool ?? makeTool({ execute })], {
    getRules: async () => options.rules ?? [],
    authorizeResource: options.authorizeResource ?? (async () => true),
    verifyAndConsumeApproval: options.verifyAndConsumeApproval ?? (async () => false),
    recordApprovalRequest: options.recordApprovalRequest ?? (async ({ request }) => { approvalRequests.push(request); }),
    claimExecution: options.claimExecution ?? (async ({ agent: principal, request }) => {
      const key = `${principal.organizationId}:${request.id}`;
      if (claims.has(key)) return false;
      claims.add(key);
      return true;
    }),
    appendAudit: options.appendAudit ?? (async (event) => { events.push(event); }),
  });
  return { gate, events, execute, claims, approvalRequests };
}
const invoke = (overrides: Partial<{ requestId: string; agent: AuthenticatedAgent; toolName: string; input: unknown; approval: { requestId: string; approvalId: string } }> = {}) => ({
  requestId: "request-1", agent, toolName: "documents.read", input: { resource: "docs/readme.md" }, ...overrides,
});

describe("server execution gate", () => {
  it("executes a registered read only after policy and resource authorization", async () => {
    const authorizeResource = vi.fn(async () => true);
    const h = harness({ authorizeResource });
    const result = await h.gate.invoke<string>(invoke());
    expect(result.status).toBe("executed");
    if (result.status !== "executed") return;
    expect(result.output).toBe("docs/readme.md");
    expect(result.request.inputDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.auditComplete).toBe(true);
    expect(authorizeResource).toHaveBeenCalledOnce();
    expect(h.execute).toHaveBeenCalledOnce();
    expect(h.events.map((event) => event.kind)).toEqual(["EXECUTION_AUTHORIZED", "EXECUTION_SUCCEEDED"]);
  });

  it("does not execute the same request ID twice", async () => {
    const h = harness();
    const first = await h.gate.invoke<string>(invoke());
    const second = await h.gate.invoke<string>(invoke({ input: { resource: "docs/changed.md", message: "different payload" } }));
    expect(first.status).toBe("executed");
    expect(second.status).toBe("blocked");
    expect(h.execute).toHaveBeenCalledOnce();
    expect(h.events.some((event) => event.kind === "BLOCKED" && event.reason.includes("already claimed"))).toBe(true);
  });

  it("fails closed when the durable execution-claim store is unavailable", async () => {
    const execute = vi.fn(async (input: Input) => input.resource);
    const h = harness({ tool: makeTool({ execute }), claimExecution: async () => { throw new Error("storage unavailable"); } });
    const result = await h.gate.invoke(invoke());
    expect(result.status).toBe("error");
    expect(execute).not.toHaveBeenCalled();
  });

  it("never executes a baseline-blocked deletion even when the principal has the action", async () => {
    const tool = makeTool({ name: "documents.delete", actionType: "delete_resource" });
    const h = harness({ tool });
    const result = await h.gate.invoke(invoke({ toolName: "documents.delete" }));
    expect(result.status).toBe("blocked");
    expect(h.execute).not.toHaveBeenCalled();
    expect(h.events[0].kind).toBe("BLOCKED");
  });

  it("persists a pending approval request and does not execute without evidence", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const h = harness({ tool });
    const result = await h.gate.invoke(invoke({ toolName: "mail.send" }));
    expect(result.status).toBe("approval_required");
    expect(h.execute).not.toHaveBeenCalled();
    expect(h.events[0].kind).toBe("APPROVAL_REQUIRED");
    expect(h.approvalRequests).toHaveLength(1);
    expect(h.approvalRequests[0].inputDigest).toMatch(/^[a-f0-9]{64}$/);
  });

  it("blocks an action when the durable approval queue cannot save the review request", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const h = harness({ tool, recordApprovalRequest: async () => { throw new Error("database unavailable"); } });
    const result = await h.gate.invoke(invoke({ toolName: "mail.send" }));
    expect(result.status).toBe("error");
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("executes a reviewed action only after trusted approval verification", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const verifyAndConsumeApproval = vi.fn(async ({ request, inputDigest, approval }: { request: GuardedActionRequest; inputDigest: string; approval: { requestId: string; approvalId: string } }) => request.id === approval.requestId && request.inputDigest === inputDigest && /^[a-f0-9]{64}$/.test(inputDigest) && approval.approvalId === "approval-1");
    const h = harness({ tool, verifyAndConsumeApproval });
    const result = await h.gate.invoke<string>(invoke({
      toolName: "mail.send",
      approval: { requestId: "request-1", approvalId: "approval-1" },
    }));
    expect(result.status).toBe("executed");
    expect(verifyAndConsumeApproval).toHaveBeenCalledOnce();
    expect(h.execute).toHaveBeenCalledOnce();
  });

  it("rejects an approval for a different request ID", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const verifyAndConsumeApproval = vi.fn(async () => true);
    const h = harness({ tool, verifyAndConsumeApproval });
    const result = await h.gate.invoke(invoke({
      toolName: "mail.send",
      approval: { requestId: "another-request", approvalId: "approval-1" },
    }));
    expect(result.status).toBe("approval_required");
    expect(verifyAndConsumeApproval).not.toHaveBeenCalled();
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("blocks tools not allowed for the authenticated principal", async () => {
    const h = harness();
    const result = await h.gate.invoke(invoke({
      agent: { ...agent, allowedActions: ["delete_resource"] },
    }));
    expect(result.status).toBe("blocked");
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("blocks a denied resource even when baseline policy allows the action", async () => {
    const h = harness({ authorizeResource: async () => false });
    const result = await h.gate.invoke(invoke());
    expect(result.status).toBe("blocked");
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("fails closed if the audit sink fails before execution", async () => {
    const execute = vi.fn(async (input: Input) => input.resource);
    const h = harness({ tool: makeTool({ execute }), appendAudit: async () => { throw new Error("storage unavailable"); } });
    const result = await h.gate.invoke(invoke());
    expect(result.status).toBe("error");
    expect(execute).not.toHaveBeenCalled();
  });

  it("fails closed when policy storage is unavailable", async () => {
    const execute = vi.fn(async (input: Input) => input.resource);
    const h = harness({ tool: makeTool({ execute }), rules: undefined });
    const getRulesGate = createExecutionGate([makeTool({ execute })], {
      getRules: async () => { throw new Error("storage unavailable"); },
      authorizeResource: async () => true,
      verifyAndConsumeApproval: async () => false,
      recordApprovalRequest: async () => {},
      claimExecution: async () => true,
      appendAudit: async (event) => { h.events.push(event); },
    });
    const result = await getRulesGate.invoke(invoke());
    expect(result.status).toBe("error");
    expect(execute).not.toHaveBeenCalled();
  });

  it("does not pass mutable caller data to the executor", async () => {
    let observedFrozen = false;
    const execute = vi.fn(async (input: Input) => { observedFrozen = Object.isFrozen(input); return input.resource; });
    const h = harness({ tool: makeTool({ execute }) });
    const raw = { resource: "docs/readme.md" };
    const invocation = invoke({ input: raw });
    const resultPromise = h.gate.invoke(invocation);
    raw.resource = "docs/secret.md";
    const result = await resultPromise;
    expect(result.status).toBe("executed");
    expect(observedFrozen).toBe(true);
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ resource: "docs/readme.md" }), expect.any(Object));
  });

  it("rejects unknown tools and invalid request IDs", async () => {
    const h = harness();
    expect((await h.gate.invoke(invoke({ toolName: "arbitrary.exec" }))).status).toBe("blocked");
    expect((await h.gate.invoke(invoke({ requestId: "bad\nrequest" }))).status).toBe("error");
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("does not execute when a rule requires approval even if audit logs work", async () => {
    const tool = makeTool({ name: "documents.write", actionType: "write_resource" });
    const h = harness({ tool });
    const result = await h.gate.invoke(invoke({ toolName: "documents.write" }));
    expect(result.status).toBe("approval_required");
    expect(h.execute).not.toHaveBeenCalled();
  });
});
