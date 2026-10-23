import { describe, expect, it, vi } from "vitest";
import {
  createPostgresExecutionGateDependencies,
  type PgConnection,
  type PgPool,
  type PgQueryResult,
} from "./postgres-adapter.js";
import type { GateAuditEvent, GuardedActionRequest } from "./execution-gate.js";

type Row = Record<string, unknown>;
const digest = "a".repeat(64);
const agent = { id: "agent-1", organizationId: "org-1", allowedActions: ["read_resource", "send_external"] as const };
const request: GuardedActionRequest = {
  id: "request-1",
  agent: agent.id,
  toolName: "mail.send",
  actionType: "send_external",
  resource: "mail/customer-123",
  summary: "Send an approved message",
  requestedAt: "2026-10-23T00:00:00.000Z",
  inputDigest: digest,
  policyVersion: "backstop-baseline-1.0.1;org=policy-v4",
};
const approvalRow = (overrides: Row = {}): Row => ({
  organization_id: agent.organizationId,
  request_id: request.id,
  agent_id: agent.id,
  tool_name: request.toolName,
  action_type: request.actionType,
  resource: request.resource,
  summary: request.summary,
  input_digest: digest,
  policy_version: request.policyVersion,
  status: "approved",
  reviewer_id: "reviewer-1",
  approval_id: "approval-1",
  expires_at: new Date(Date.now() + 60_000),
  ...overrides,
});

class FakePool implements PgPool {
  policyVersion: string | null = "policy-v4";
  policyRules: Row[] = [{
    rule_id: "send-review",
    name: "Review outbound messages",
    description: "External messages require approval.",
    effect: "REQUIRE_APPROVAL",
    action_types: ["send_external"],
    resource_patterns: ["*"],
    enabled: true,
    priority: 200,
  }];
  approval: Row | null = null;
  claimed = false;
  queries: Array<{ sql: string; values: unknown[] }> = [];

  async query<T extends Record<string, unknown> = Row>(
    text: string,
    values: unknown[] = [],
  ): Promise<PgQueryResult<T>> {
    const sql = text.replace(/\s+/g, " ").trim().toLowerCase();
    this.queries.push({ sql, values });
    let rows: Row[] = [];

    if (sql.includes("from backstop_policy_sets")) {
      rows = this.policyVersion === null ? [] : [{ policy_version: this.policyVersion }];
    } else if (sql.includes("from backstop_policy_rules")) {
      rows = this.policyRules;
    } else if (sql.startsWith("insert into backstop_execution_claims")) {
      if (!this.claimed) {
        this.claimed = true;
        rows = [{ request_id: values[1] }];
      }
    } else if (sql.startsWith("insert into backstop_approval_requests")) {
      if (!this.approval) {
        this.approval = {
          organization_id: values[0], request_id: values[1], agent_id: values[2],
          tool_name: values[3], action_type: values[4], resource: values[5], summary: values[6],
          input_digest: values[7], policy_version: values[8], status: "pending",
          reviewer_id: null, approval_id: null, expires_at: new Date(Date.now() + Number(values[9]) * 1000),
        };
        rows = [{ request_id: values[1] }];
      }
    } else if (sql.includes("from backstop_approval_requests")) {
      const [organizationId, requestId, approvalId] = values;
      if (this.approval
        && this.approval.organization_id === organizationId
        && this.approval.request_id === requestId
        && (!approvalId || this.approval.approval_id === approvalId)
        && this.approval.status === "approved"
        && new Date(String(this.approval.expires_at)).getTime() > Date.now()) {
        rows = [this.approval];
      } else if (this.approval
        && this.approval.organization_id === organizationId
        && this.approval.request_id === requestId
        && !approvalId) {
        rows = [this.approval];
      }
    } else if (sql.startsWith("update backstop_approval_requests")) {
      if (this.approval && this.approval.organization_id === values[0]
        && this.approval.request_id === values[1] && this.approval.approval_id === values[2]
        && this.approval.status === "approved") {
        this.approval = { ...this.approval, status: "consumed" };
        rows = [{ request_id: values[1] }];
      }
    }
    return { rows: rows as T[] };
  }

  async connect(): Promise<PgConnection> {
    return {
      query: <T extends Record<string, unknown> = Row>(text: string, values: unknown[] = []) =>
        this.query<T>(text, values),
      release: () => undefined,
    };
  }
}

function makeDependencies(pool: FakePool) {
  return createPostgresExecutionGateDependencies(pool, {
    authorizeResource: async () => true,
    authorizeReviewer: async ({ organizationId, reviewerId }) =>
      organizationId === agent.organizationId && reviewerId === "reviewer-1",
    approvalTtlSeconds: 300,
  });
}

describe("PostgreSQL execution gate adapter", () => {
  it("loads a versioned restrictive policy snapshot", async () => {
    const pool = new FakePool();
    const dependencies = makeDependencies(pool);
    const policy = await dependencies.getRules(agent);
    expect(policy.version).toBe("policy-v4");
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].effect).toBe("REQUIRE_APPROVAL");
    expect(policy.rules[0].actionTypes).toEqual(["send_external"]);
    expect(pool.queries.every((query) => !query.sql.includes("$orgid"))).toBe(true);
  });

  it("uses the built-in baseline when an organization has no stored policy set", async () => {
    const pool = new FakePool();
    pool.policyVersion = null;
    const policy = await makeDependencies(pool).getRules(agent);
    expect(policy).toEqual({ version: "baseline", rules: [] });
    expect(pool.queries).toHaveLength(1);
  });

  it("fails closed when the database contains an unsupported ALLOW custom rule", async () => {
    const pool = new FakePool();
    pool.policyRules = [{ ...pool.policyRules[0], effect: "ALLOW" }];
    await expect(makeDependencies(pool).getRules(agent)).rejects.toThrow("Stored custom policy may not grant ALLOW permissions.");
  });

  it("persists the pending approval once and refuses the same ID with a different payload", async () => {
    const pool = new FakePool();
    const dependencies = makeDependencies(pool);
    const evaluation = {
      decision: "REQUIRE_APPROVAL" as const,
      reason: "Review this action.",
      matchedRules: [],
      policyVersion: request.policyVersion,
    };
    await dependencies.recordApprovalRequest({ agent, request, evaluation });
    await expect(dependencies.recordApprovalRequest({
      agent,
      request: { ...request, inputDigest: "b".repeat(64) },
      evaluation,
    })).rejects.toThrow("A conflicting, expired, or already-used approval request ID exists.");
    expect(pool.queries.filter((query) => query.sql.startsWith("insert into backstop_approval_requests")).length).toBe(2);
  });

  it("atomically consumes an approval bound to the exact request and input digest", async () => {
    const pool = new FakePool();
    pool.approval = approvalRow();
    const dependencies = makeDependencies(pool);
    const consumed = await dependencies.verifyAndConsumeApproval({
      agent, request, inputDigest: digest, approval: { requestId: request.id, approvalId: "approval-1" },
    });
    expect(consumed).toBe(true);
    expect(pool.approval?.status).toBe("consumed");
    expect(pool.queries.map((query) => query.sql).filter((sql) => ["begin", "commit"].includes(sql))).toEqual(["begin", "commit"]);
  });

  it("does not re-use a consumed approval", async () => {
    const pool = new FakePool();
    pool.approval = approvalRow({ status: "consumed" });
    const dependencies = makeDependencies(pool);
    const consumed = await dependencies.verifyAndConsumeApproval({
      agent, request, inputDigest: digest, approval: { requestId: request.id, approvalId: "approval-1" },
    });
    expect(consumed).toBe(false);
  });

  it("atomically claims each organization/request pair once", async () => {
    const pool = new FakePool();
    const dependencies = makeDependencies(pool);
    expect(await dependencies.claimExecution({ agent, request, toolName: request.toolName })).toBe(true);
    expect(await dependencies.claimExecution({ agent, request, toolName: request.toolName })).toBe(false);
  });

  it("writes audit events through parameterized SQL", async () => {
    const pool = new FakePool();
    const event: GateAuditEvent = {
      occurredAt: "2026-10-23T00:00:00.000Z",
      requestId: request.id,
      organizationId: agent.organizationId,
      agentId: agent.id,
      toolName: request.toolName,
      kind: "EXECUTION_AUTHORIZED",
      decision: "ALLOW",
      policyVersion: request.policyVersion,
      actionType: request.actionType,
      resource: request.resource,
      inputDigest: digest,
      reason: "Approved by policy.",
    };
    await makeDependencies(pool).appendAudit(event);
    const query = pool.queries[0];
    expect(query.sql).toContain("insert into backstop_audit_events");
    expect(query.sql).not.toContain(request.id);
    expect(query.values).toContain(request.id);
    expect(query.values).toContain(digest);
  });
});
