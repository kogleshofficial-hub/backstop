import { describe, expect, it } from "vitest";
import {
  createPostgresAgentCredentialService,
  createPostgresExecutionGateDependencies,
  createPostgresPolicyService,
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
  policySetWritten = false;
  credentials: Row[] = [];
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

    if (sql.includes("from backstop_policy_sets ps left join backstop_policy_rules")) {
      if (this.policyVersion !== null) {
        const versionedRules = this.policyRules.filter((rule) => rule.policy_version === this.policyVersion);
        const selectedRules = versionedRules.length
          ? versionedRules
          : this.policySetWritten ? [] : this.policyRules.filter((rule) => rule.policy_version === undefined);
        rows = selectedRules.length
          ? selectedRules.map((rule) => ({ ...rule, policy_version: this.policyVersion }))
          : [{ policy_version: this.policyVersion, rule_id: null }];
      }
    } else if (sql.startsWith("insert into backstop_policy_sets")) {
      this.policyVersion = String(values[1]);
      this.policySetWritten = true;
    } else if (sql.startsWith("insert into backstop_policy_rules")) {
      this.policyRules.push({
        organization_id: values[0], policy_version: values[1], rule_id: values[2],
        name: values[3], description: values[4], effect: values[5], action_types: values[6],
        resource_patterns: values[7], enabled: values[8], priority: values[9],
      });
    } else if (sql.includes("from backstop_policy_sets")) {
      rows = this.policyVersion === null ? [] : [{ policy_version: this.policyVersion }];
    } else if (sql.includes("from backstop_policy_rules")) {
      rows = this.policyRules;
    } else if (sql.startsWith("insert into backstop_agent_credentials")) {
      const row: Row = {
        credential_id: values[0], organization_id: values[1], agent_id: values[2],
        key_prefix: values[3], token_hash: values[4], allowed_actions: values[5],
        status: "active", created_by: values[6], created_at: new Date(),
        last_used_at: null, expires_at: values[7], revoked_at: null,
      };
      this.credentials.push(row);
      rows = [row];
    } else if (sql.includes("from backstop_agent_credentials")) {
      if (sql.includes("token_hash = $1")) {
        rows = this.credentials.filter((row) => row.token_hash === values[0]
          && row.status === "active" && new Date(String(row.expires_at)).getTime() > Date.now());
      } else if (sql.includes("credential_id = $2")) {
        rows = this.credentials.filter((row) => row.organization_id === values[0]
          && row.credential_id === values[1] && row.status === "active");
      } else {
        rows = this.credentials.filter((row) => row.organization_id === values[0]);
        rows.sort((a,b) => new Date(String(b.created_at)).getTime() - new Date(String(a.created_at)).getTime());
      }
    } else if (sql.startsWith("update backstop_agent_credentials")) {
      if (sql.includes("set last_used_at")) {
        const target = this.credentials.find((candidate) => candidate.credential_id === values[0] && candidate.status === "active");
        if (target && new Date(String(target.expires_at)).getTime() > Date.now()) {
          target.last_used_at = new Date();
          rows = [{ credential_id: values[0] }];
        }
      } else if (sql.includes("set status = 'revoked'")) {
        // Credential revocation SQL uses [organizationId, credentialId].
        const target = this.credentials.find((candidate) => candidate.organization_id === values[0] && candidate.credential_id === values[1] && candidate.status === "active");
        if (target) { target.status = "revoked"; target.revoked_at = new Date(); rows = [{ credential_id: values[1] }]; }
      }
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
  it("creates expiring credentials with one-time secrets and stores only a hash", async () => {
    const pool = new FakePool();
    const service = createPostgresAgentCredentialService(pool, {
      authorizeCredentialManagement: async ({ organizationId, actorId }) =>
        organizationId === agent.organizationId && actorId === "admin-1",
      defaultTtlSeconds: 3600,
    });
    const created = await service.create({
      organizationId: agent.organizationId,
      actorId: "admin-1",
      agentId: "agent-workflow",
      allowedActions: ["read_resource", "search"],
    });
    expect(created.secret).toMatch(/^bsk_live_[A-Za-z0-9_-]{43}$/);
    expect(created.keyPrefix).toMatch(/^bsk_live_[A-Za-z0-9_-]{8}$/);
    expect(created.secret).not.toBe(pool.credentials[0].token_hash);
    expect(pool.credentials[0].token_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(pool.credentials[0].token_hash).not.toContain(created.secret);
    expect(pool.queries.some((query) => query.sql.includes("insert into backstop_audit_events"))).toBe(true);
  });

  it("authenticates a credential into a server-side agent principal and scopes permissions", async () => {
    const pool = new FakePool();
    const service = createPostgresAgentCredentialService(pool, {
      authorizeCredentialManagement: async () => true,
    });
    const created = await service.create({
      organizationId: agent.organizationId,
      actorId: "admin-1",
      agentId: "agent-workflow",
      allowedActions: ["read_resource", "search"],
      ttlSeconds: 3600,
    });
    const authenticated = await service.authenticate(created.secret);
    expect(authenticated?.agent).toEqual({
      id: "agent-workflow",
      organizationId: agent.organizationId,
      allowedActions: ["read_resource", "search"],
    });
    expect(await service.authenticate("invalid-token")).toBeNull();
    expect((await service.list({ organizationId: agent.organizationId, actorId: "admin-1" })).length).toBe(1);
  });

  it("revokes a credential and rejects it on the next authentication", async () => {
    const pool = new FakePool();
    const service = createPostgresAgentCredentialService(pool, {
      authorizeCredentialManagement: async () => true,
    });
    const created = await service.create({
      organizationId: agent.organizationId,
      actorId: "admin-1",
      agentId: "agent-workflow",
      allowedActions: ["read_resource"],
      ttlSeconds: 3600,
    });
    expect(await service.revoke({
      organizationId: agent.organizationId, actorId: "admin-1", credentialId: created.credentialId,
    })).toBe(true);
    expect(await service.authenticate(created.secret)).toBeNull();
    expect(pool.queries.some((query) => query.sql.includes("insert into backstop_audit_events"))).toBe(true);
  });

  it("refuses credential creation without organization administrator authorization", async () => {
    const service = createPostgresAgentCredentialService(new FakePool(), {
      authorizeCredentialManagement: async () => false,
    });
    await expect(service.create({
      organizationId: agent.organizationId, actorId: "untrusted", agentId: "agent",
      allowedActions: ["read_resource"],
    })).rejects.toThrow("Credential management is not authorized");
  });

  it("publishes a versioned organization policy in one transaction and loads that revision", async () => {
    const pool = new FakePool();
    const service = createPostgresPolicyService(pool, {
      authorizePolicyManagement: async ({ organizationId, actorId }) =>
        organizationId === agent.organizationId && actorId === "admin-1",
    });
    const published = await service.publish({
      organizationId: agent.organizationId,
      actorId: "admin-1",
      rules: [{
        id: "block-private",
        name: "Block private exports",
        description: "Private exports must never leave the workspace.",
        effect: "BLOCK",
        actionTypes: ["send_external"],
        resources: ["exports/private/**"],
        enabled: true,
        priority: 400,
      }],
    });
    expect(published.version).toMatch(/^org_[a-f0-9]{32}$/);
    expect(pool.queries.map((query) => query.sql).filter((sql) => ["begin", "commit"].includes(sql))).toEqual(["begin", "commit"]);
    const current = await service.loadCurrent(agent.organizationId);
    expect(current.version).toBe(published.version);
    expect(current.rules).toHaveLength(1);
    expect(current.rules[0].effect).toBe("BLOCK");
    expect(current.rules[0].resources).toEqual(["exports/private/**"]);
  });

  it("refuses policies that attempt to create custom ALLOW permissions", async () => {
    const pool = new FakePool();
    const service = createPostgresPolicyService(pool, {
      authorizePolicyManagement: async () => true,
    });
    await expect(service.publish({
      organizationId: agent.organizationId,
      actorId: "admin-1",
      rules: [{
        id: "allow-everything",
        name: "Allow everything",
        description: "Invalid custom permission grant.",
        effect: "ALLOW",
        actionTypes: ["delete_resource"],
        resources: ["*"],
        enabled: true,
        priority: 1,
      }],
    })).rejects.toThrow("Custom organization policies cannot grant ALLOW permissions.");
    expect(pool.policySetWritten).toBe(false);
  });

  it("refuses policy publication without organization-admin authorization", async () => {
    const service = createPostgresPolicyService(new FakePool(), {
      authorizePolicyManagement: async () => false,
    });
    await expect(service.publish({
      organizationId: agent.organizationId,
      actorId: "untrusted",
      rules: [],
    })).rejects.toThrow("Policy management is not authorized");
  });

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
