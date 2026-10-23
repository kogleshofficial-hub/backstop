import { describe, expect, it, vi } from "vitest";
import { createExecutionGate, type AuthenticatedAgent, type GateAuditEvent, type GuardedTool } from "./execution-gate.js";
import type { ActionRequest, PolicyRule } from "./index.js";

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
  verifyApproval?: (args: { agent: AuthenticatedAgent; request: ActionRequest; approval: { requestId: string; approvalId: string } }) => Promise<boolean>;
  appendAudit?: (event: GateAuditEvent) => Promise<void>;
} = {}) {
  const events: GateAuditEvent[] = [];
  const execute = options.tool?.execute ?? vi.fn(async (input: Input) => input.resource);
  const gate = createExecutionGate([options.tool ?? makeTool({ execute })], {
    getRules: async () => options.rules ?? [],
    authorizeResource: options.authorizeResource ?? (async () => true),
    verifyApproval: options.verifyApproval ?? (async () => false),
    appendAudit: options.appendAudit ?? (async (event) => { events.push(event); }),
  });
  return { gate, events, execute };
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
    expect(result.auditComplete).toBe(true);
    expect(authorizeResource).toHaveBeenCalledOnce();
    expect(h.execute).toHaveBeenCalledOnce();
    expect(h.events.map((event) => event.kind)).toEqual(["EXECUTION_AUTHORIZED", "EXECUTION_SUCCEEDED"]);
  });

  it("never executes a baseline-blocked deletion even when the principal has the action", async () => {
    const tool = makeTool({ name: "documents.delete", actionType: "delete_resource" });
    const h = harness({ tool });
    const result = await h.gate.invoke(invoke({ toolName: "documents.delete" }));
    expect(result.status).toBe("blocked");
    expect(h.execute).not.toHaveBeenCalled();
    expect(h.events[0].kind).toBe("BLOCKED");
  });

  it("requires approval for sensitive actions and does not execute without evidence", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const h = harness({ tool });
    const result = await h.gate.invoke(invoke({ toolName: "mail.send" }));
    expect(result.status).toBe("approval_required");
    expect(h.execute).not.toHaveBeenCalled();
    expect(h.events[0].kind).toBe("APPROVAL_REQUIRED");
  });

  it("executes a reviewed action only after trusted approval verification", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const verifyApproval = vi.fn(async ({ request, approval }: { request: ActionRequest; approval: { requestId: string; approvalId: string } }) => request.id === approval.requestId && approval.approvalId === "approval-1");
    const h = harness({ tool, verifyApproval });
    const result = await h.gate.invoke<string>(invoke({
      toolName: "mail.send",
      approval: { requestId: "request-1", approvalId: "approval-1" },
    }));
    expect(result.status).toBe("executed");
    expect(verifyApproval).toHaveBeenCalledOnce();
    expect(h.execute).toHaveBeenCalledOnce();
  });

  it("rejects an approval for a different request ID", async () => {
    const tool = makeTool({ name: "mail.send", actionType: "send_external" });
    const verifyApproval = vi.fn(async () => true);
    const h = harness({ tool, verifyApproval });
    const result = await h.gate.invoke(invoke({
      toolName: "mail.send",
      approval: { requestId: "another-request", approvalId: "approval-1" },
    }));
    expect(result.status).toBe("approval_required");
    expect(verifyApproval).not.toHaveBeenCalled();
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
      verifyApproval: async () => false,
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
