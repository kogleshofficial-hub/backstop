import {
  ACTION_CATALOG,
  type ActionType,
  type PolicyRule,
} from "./index.js";
import type {
  AuthenticatedAgent,
  ExecutionGateDependencies,
  GateAuditEvent,
  GuardedActionRequest,
} from "./execution-gate.js";

export interface PgQueryResult<Row extends Record<string, unknown> = Record<string, unknown>> {
  rows: Row[];
}

export interface PgConnection {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<Row>>;
  release(): void;
}

export interface PgPool {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<Row>>;
  connect(): Promise<PgConnection>;
}

export interface PostgresExecutionGateOptions {
  /** Must enforce the application's real object-level and tenant-level permissions. */
  authorizeResource: ExecutionGateDependencies["authorizeResource"];
  /** Must verify the reviewer is permitted to approve requests for this organization. */
  authorizeReviewer(input: { organizationId: string; reviewerId: string }): Promise<boolean>;
  /** Pending approval lifetime in seconds. Defaults to 15 minutes; maximum is 7 days. */
  approvalTtlSeconds?: number;
}

interface StoredRuleRow extends Record<string, unknown> {
  rule_id: unknown;
  name: unknown;
  description: unknown;
  effect: unknown;
  action_types: unknown;
  resource_patterns: unknown;
  enabled: unknown;
  priority: unknown;
}

interface StoredApprovalRow extends Record<string, unknown> {
  organization_id: unknown;
  request_id: unknown;
  agent_id: unknown;
  tool_name: unknown;
  action_type: unknown;
  resource: unknown;
  summary: unknown;
  input_digest: unknown;
  policy_version: unknown;
  status: unknown;
  reviewer_id: unknown;
  expires_at: unknown;
}

const knownActions = new Set<string>(ACTION_CATALOG.map((action) => action.type));
const DIGEST = /^[a-f0-9]{64}$/;

function nonEmptyString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Invalid persisted BACKSTOP field: ${name}.`);
  }
  return value;
}

function isActionType(value: unknown): value is ActionType {
  return typeof value === "string" && knownActions.has(value);
}

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length === 0
    || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new Error(`Invalid persisted BACKSTOP field: ${name}.`);
  }
  return value as string[];
}

function mapPolicyRule(row: StoredRuleRow): PolicyRule {
  const effect = row.effect;
  if (effect !== "BLOCK" && effect !== "REQUIRE_APPROVAL") {
    throw new Error("Stored custom policy may not grant ALLOW permissions.");
  }
  const actionTypes = stringArray(row.action_types, "action_types");
  if (!actionTypes.every(isActionType)) {
    throw new Error("Stored custom policy contains an unknown action type.");
  }
  if (typeof row.enabled !== "boolean" || typeof row.priority !== "number" || !Number.isFinite(row.priority)) {
    throw new Error("Stored custom policy contains an invalid enabled/priority value.");
  }
  return {
    id: nonEmptyString(row.rule_id, "rule_id"),
    name: nonEmptyString(row.name, "name"),
    description: nonEmptyString(row.description, "description"),
    effect,
    actionTypes: actionTypes as ActionType[],
    resources: stringArray(row.resource_patterns, "resource_patterns"),
    enabled: row.enabled,
    priority: row.priority,
    locked: false,
  };
}

function assertActionMatchesPrincipal(agent: AuthenticatedAgent, request: GuardedActionRequest): void {
  if (request.agent !== agent.id || request.actionType === undefined
    || request.toolName.trim() === "" || request.policyVersion.trim() === ""
    || !DIGEST.test(request.inputDigest)) {
    throw new Error("Guarded request identity/digest is invalid.");
  }
}

function stringsMatch(row: StoredApprovalRow, request: GuardedActionRequest, agent: AuthenticatedAgent): boolean {
  return row.organization_id === agent.organizationId
    && row.request_id === request.id
    && row.agent_id === agent.id
    && row.tool_name === request.toolName
    && row.action_type === request.actionType
    && row.resource === request.resource
    && row.summary === request.summary
    && String(row.input_digest).trim() === request.inputDigest
    && row.policy_version === request.policyVersion;
}

/**
 * Creates a PostgreSQL-backed adapter for BACKSTOP's server-side execution gate.
 * Supply a node-postgres compatible Pool (or compatible implementation) and the host
 * application's real authorization callbacks. This does not create a database or auth layer.
 */
export function createPostgresExecutionGateDependencies(
  pool: PgPool,
  options: PostgresExecutionGateOptions,
): ExecutionGateDependencies {
  if (!pool || typeof pool.query !== "function" || typeof pool.connect !== "function") {
    throw new Error("A compatible PostgreSQL pool is required.");
  }
  if (typeof options?.authorizeResource !== "function" || typeof options?.authorizeReviewer !== "function") {
    throw new Error("Resource and reviewer authorization callbacks are required.");
  }
  const ttl = options.approvalTtlSeconds ?? 900;
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 604800) {
    throw new Error("approvalTtlSeconds must be an integer between 60 and 604800.");
  }

  return {
    async getRules(agent) {
      const current = await pool.query<{ policy_version: unknown }>(
        "SELECT policy_version FROM backstop_policy_sets WHERE organization_id = $1",
        [agent.organizationId],
      );
      const rawVersion = current.rows[0]?.policy_version;
      if (rawVersion === undefined) return { version: "baseline", rules: [] };
      const version = nonEmptyString(rawVersion, "policy_version");
      const stored = await pool.query<StoredRuleRow>(
        `SELECT rule_id, name, description, effect, action_types, resource_patterns, enabled, priority
         FROM backstop_policy_rules
         WHERE organization_id = $1 AND policy_version = $2
         ORDER BY priority DESC, rule_id ASC`,
        [agent.organizationId, version],
      );
      return { version, rules: stored.rows.map(mapPolicyRule) };
    },

    authorizeResource: options.authorizeResource,

    async recordApprovalRequest({ agent, request, evaluation }) {
      assertActionMatchesPrincipal(agent, request);
      if (evaluation.decision !== "REQUIRE_APPROVAL"
        || evaluation.policyVersion !== request.policyVersion) {
        throw new Error("Only the matching review-gated policy decision may create an approval request.");
      }

      const inserted = await pool.query<{ request_id: unknown }>(
        `INSERT INTO backstop_approval_requests
           (organization_id, request_id, agent_id, tool_name, action_type, resource, summary,
            input_digest, policy_version, status, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',now() + ($10 * interval '1 second'))
         ON CONFLICT (organization_id, request_id) DO NOTHING
         RETURNING request_id`,
        [agent.organizationId, request.id, agent.id, request.toolName, request.actionType,
          request.resource, request.summary, request.inputDigest, request.policyVersion, ttl],
      );
      if (inserted.rows.length > 0) return;

      const existing = await pool.query<StoredApprovalRow>(
        `SELECT organization_id, request_id, agent_id, tool_name, action_type, resource, summary,
                input_digest, policy_version, status, reviewer_id, expires_at
         FROM backstop_approval_requests
         WHERE organization_id = $1 AND request_id = $2`,
        [agent.organizationId, request.id],
      );
      const row = existing.rows[0];
      if (!row || !stringsMatch(row, request, agent)
        || !["pending", "approved"].includes(String(row.status))
        || !(row.expires_at instanceof Date ? row.expires_at.getTime() > Date.now() : new Date(String(row.expires_at)).getTime() > Date.now())) {
        throw new Error("A conflicting, expired, or already-used approval request ID exists.");
      }
      // Idempotent duplicate of the same still-open request. Never overwrite its status/digest.
    },

    async verifyAndConsumeApproval({ agent, request, inputDigest, approval }) {
      assertActionMatchesPrincipal(agent, request);
      if (inputDigest !== request.inputDigest || approval.requestId !== request.id) return false;

      const client = await pool.connect();
      let begun = false;
      try {
        await client.query("BEGIN");
        begun = true;
        const selected = await client.query<StoredApprovalRow>(
          `SELECT organization_id, request_id, agent_id, tool_name, action_type, resource, summary,
                  input_digest, policy_version, status, reviewer_id, expires_at
           FROM backstop_approval_requests
           WHERE organization_id = $1 AND request_id = $2 AND approval_id = $3
             AND status = 'approved' AND expires_at > now()
           FOR UPDATE`,
          [agent.organizationId, request.id, approval.approvalId],
        );
        const row = selected.rows[0];
        if (!row || !stringsMatch(row, request, agent) || !DIGEST.test(String(row.input_digest).trim())
          || typeof row.reviewer_id !== "string" || !row.reviewer_id.trim()) {
          await client.query("ROLLBACK");
          begun = false;
          return false;
        }
        const reviewerAuthorized = await options.authorizeReviewer({
          organizationId: agent.organizationId,
          reviewerId: row.reviewer_id,
        });
        if (!reviewerAuthorized) {
          await client.query("ROLLBACK");
          begun = false;
          return false;
        }
        const consumed = await client.query<{ request_id: unknown }>(
          `UPDATE backstop_approval_requests
           SET status = 'consumed', consumed_at = now(), updated_at = now()
           WHERE organization_id = $1 AND request_id = $2 AND approval_id = $3
             AND status = 'approved' AND expires_at > now()
           RETURNING request_id`,
          [agent.organizationId, request.id, approval.approvalId],
        );
        if (consumed.rows.length !== 1) {
          await client.query("ROLLBACK");
          begun = false;
          return false;
        }
        await client.query("COMMIT");
        begun = false;
        return true;
      } catch (error) {
        if (begun) {
          try { await client.query("ROLLBACK"); } catch { /* Preserve the original database error. */ }
        }
        throw error;
      } finally {
        client.release();
      }
    },

    async claimExecution({ agent, request, toolName }) {
      assertActionMatchesPrincipal(agent, request);
      if (toolName !== request.toolName) throw new Error("Execution tool name does not match the bound request.");
      const inserted = await pool.query<{ request_id: unknown }>(
        `INSERT INTO backstop_execution_claims
           (organization_id, request_id, agent_id, tool_name, action_type, resource, input_digest)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (organization_id, request_id) DO NOTHING
         RETURNING request_id`,
        [agent.organizationId, request.id, agent.id, request.toolName, request.actionType,
          request.resource, request.inputDigest],
      );
      return inserted.rows.length === 1;
    },

    async appendAudit(event: GateAuditEvent) {
      await pool.query(
        `INSERT INTO backstop_audit_events
           (occurred_at, organization_id, request_id, agent_id, tool_name, kind, decision,
            policy_version, action_type, resource, input_digest, reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [event.occurredAt, event.organizationId, event.requestId, event.agentId,
          event.toolName, event.kind, event.decision, event.policyVersion,
          event.actionType ?? null, event.resource ?? null, event.inputDigest ?? null, event.reason],
      );
    },
  };
}
