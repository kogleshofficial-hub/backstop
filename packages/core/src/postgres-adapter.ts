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
      // One SQL statement gives policy version and rules one MVCC snapshot. A multi-query
      // read could accidentally combine a just-changed version with stale rows.
      const current = await pool.query<StoredRuleRow & { policy_version: unknown }>(
        `SELECT ps.policy_version, r.rule_id, r.name, r.description, r.effect,
                r.action_types, r.resource_patterns, r.enabled, r.priority
         FROM backstop_policy_sets ps
         LEFT JOIN backstop_policy_rules r
           ON r.organization_id = ps.organization_id AND r.policy_version = ps.policy_version
         WHERE ps.organization_id = $1
         ORDER BY r.priority DESC NULLS LAST, r.rule_id ASC NULLS LAST`,
        [agent.organizationId],
      );
      if (current.rows.length === 0) return { version: "baseline", rules: [] };
      const version = nonEmptyString(current.rows[0].policy_version, "policy_version");
      const rules = current.rows
        .filter((row) => row.rule_id !== null && row.rule_id !== undefined)
        .map(mapPolicyRule);
      return { version, rules };
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
         WHERE organization_id = $1 AND request_id = $2 AND expires_at > now()`,
        [agent.organizationId, request.id],
      );
      const row = existing.rows[0];
      if (!row || !stringsMatch(row, request, agent)
        || !["pending", "approved"].includes(String(row.status))) {
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


export interface ApprovalQueueItem {
  requestId: string;
  agentId: string;
  toolName: string;
  actionType: ActionType;
  resource: string;
  summary: string;
  inputDigest: string;
  policyVersion: string;
  createdAt: string;
  expiresAt: string;
}

export interface ApprovalReviewResult {
  status: "approved" | "rejected";
  requestId: string;
  approval?: { requestId: string; approvalId: string };
}

export interface PostgresApprovalServiceOptions {
  /** Always pass reviewer identity obtained from trusted server-side authentication. */
  authorizeReviewer(input: { organizationId: string; reviewerId: string }): Promise<boolean>;
}

function toIso(value: unknown, field: string): string {
  const date = value instanceof Date ? value : new Date(String(value));
  if (!Number.isFinite(date.getTime())) throw new Error(`Invalid stored timestamp: ${field}.`);
  return date.toISOString();
}

function secureApprovalId(): string {
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new Error("A cryptographically secure UUID generator is required for approval IDs.");
  }
  return `bsa_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
}

/**
 * Durable approval queue for trusted server routes.
 *
 * Call listPending only after the route has authenticated a reviewer and resolved the
 * organization from trusted membership data. Call review with the reviewer ID from that
 * same authenticated session, never from request JSON.
 */
export function createPostgresApprovalService(
  pool: PgPool,
  options: PostgresApprovalServiceOptions,
) {
  if (!pool || typeof pool.query !== "function" || typeof pool.connect !== "function") {
    throw new Error("A compatible PostgreSQL pool is required.");
  }
  if (typeof options?.authorizeReviewer !== "function") {
    throw new Error("A reviewer authorization callback is required.");
  }

  return {
    async listPending(organizationId: string, limit = 20, offset = 0): Promise<ApprovalQueueItem[]> {
      if (typeof organizationId !== "string" || !organizationId.trim()) {
        throw new Error("A trusted organization ID is required.");
      }
      if (!Number.isInteger(limit) || limit < 1 || limit > 100
        || !Number.isInteger(offset) || offset < 0 || offset > 100000) {
        throw new Error("Pagination limit must be 1–100 and offset must be between 0 and 100000.");
      }
      const result = await pool.query<StoredApprovalRow & {
        created_at: unknown;
        expires_at: unknown;
      }>(
        `SELECT request_id, agent_id, tool_name, action_type, resource, summary, input_digest,
                policy_version, created_at, expires_at
         FROM backstop_approval_requests
         WHERE organization_id = $1 AND status = 'pending' AND expires_at > now()
         ORDER BY created_at ASC, request_id ASC
         LIMIT $2 OFFSET $3`,
        [organizationId, limit, offset],
      );
      return result.rows.map((row) => {
        if (!isActionType(row.action_type) || !DIGEST.test(String(row.input_digest).trim())) {
          throw new Error("Stored approval request contains an invalid action type or input digest.");
        }
        return {
          requestId: nonEmptyString(row.request_id, "request_id"),
          agentId: nonEmptyString(row.agent_id, "agent_id"),
          toolName: nonEmptyString(row.tool_name, "tool_name"),
          actionType: row.action_type,
          resource: nonEmptyString(row.resource, "resource"),
          summary: nonEmptyString(row.summary, "summary"),
          inputDigest: String(row.input_digest).trim(),
          policyVersion: nonEmptyString(row.policy_version, "policy_version"),
          createdAt: toIso(row.created_at, "created_at"),
          expiresAt: toIso(row.expires_at, "expires_at"),
        };
      });
    },

    async review(input: {
      organizationId: string;
      requestId: string;
      reviewerId: string;
      outcome: "approve" | "reject";
    }): Promise<ApprovalReviewResult> {
      if (!input || typeof input.organizationId !== "string" || !input.organizationId.trim()
        || typeof input.requestId !== "string" || !input.requestId.trim()
        || typeof input.reviewerId !== "string" || !input.reviewerId.trim()
        || (input.outcome !== "approve" && input.outcome !== "reject")) {
        throw new Error("Organization, request, reviewer, and decision are required.");
      }
      const client = await pool.connect();
      let begun = false;
      try {
        await client.query("BEGIN");
        begun = true;
        const selected = await client.query<StoredApprovalRow>(
          `SELECT organization_id, request_id, agent_id, tool_name, action_type, resource, summary,
                  input_digest, policy_version, status, reviewer_id, approval_id, expires_at
           FROM backstop_approval_requests
           WHERE organization_id = $1 AND request_id = $2
             AND status = 'pending' AND expires_at > now()
           FOR UPDATE`,
          [input.organizationId, input.requestId],
        );
        const row = selected.rows[0];
        if (!row) throw new Error("Approval request is missing, expired, or already reviewed.");
        if (!isActionType(row.action_type) || !DIGEST.test(String(row.input_digest).trim())) {
          throw new Error("Stored approval request contains invalid action metadata.");
        }
        // Authorize inside the transaction after the target row is locked, narrowing the
        // permission-revocation race between the reviewer check and the state transition.
        if (!await options.authorizeReviewer({
          organizationId: input.organizationId,
          reviewerId: input.reviewerId,
        })) {
          throw new Error("This reviewer is not permitted to review requests for the organization.");
        }

        const decision = input.outcome === "approve" ? "APPROVAL_APPROVED" : "APPROVAL_REJECTED";
        const nextStatus = input.outcome === "approve" ? "approved" : "rejected";
        const approvalId = input.outcome === "approve" ? secureApprovalId() : null;
        const updated = await client.query<{ request_id: unknown }>(
          `UPDATE backstop_approval_requests
           SET status = $3, reviewer_id = $4, approval_id = $5, updated_at = now()
           WHERE organization_id = $1 AND request_id = $2
             AND status = 'pending' AND expires_at > now()
           RETURNING request_id`,
          [input.organizationId, input.requestId, nextStatus, input.reviewerId, approvalId],
        );
        if (updated.rows.length !== 1) throw new Error("Approval request changed before the review could be saved.");

        await client.query(
          `INSERT INTO backstop_audit_events
             (occurred_at, organization_id, request_id, agent_id, tool_name, kind, decision,
              policy_version, action_type, resource, input_digest, reason)
           VALUES (now(),$1,$2,$3,$4,$5,'REQUIRE_APPROVAL',$6,$7,$8,$9,$10)`,
          [
            input.organizationId, input.requestId, input.reviewerId, row.tool_name, decision,
            row.policy_version, row.action_type, row.resource, String(row.input_digest).trim(),
            input.outcome === "approve" ? "Authorized reviewer approved the pending request." : "Authorized reviewer rejected the pending request.",
          ],
        );

        await client.query("COMMIT");
        begun = false;
        return input.outcome === "approve"
          ? { status: "approved", requestId: input.requestId, approval: { requestId: input.requestId, approvalId: approvalId! } }
          : { status: "rejected", requestId: input.requestId };
      } catch (error) {
        if (begun) {
          try { await client.query("ROLLBACK"); } catch { /* Preserve the original error. */ }
        }
        throw error;
      } finally {
        client.release();
      }
    },
  };
}


export interface AgentCredentialMetadata {
  credentialId: string;
  organizationId: string;
  agentId: string;
  keyPrefix: string;
  allowedActions: ActionType[];
  status: "active" | "revoked";
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
}

export interface CreatedAgentCredential extends AgentCredentialMetadata {
  /** Returned only by create(). Do not log it or send it back to the client after creation. */
  secret: string;
}

export interface AuthenticatedCredential {
  credentialId: string;
  agent: AuthenticatedAgent;
}

export interface AgentCredentialServiceOptions {
  /** Check organization-admin/credential-manager rights using trusted session identity. */
  authorizeCredentialManagement(input: { organizationId: string; actorId: string }): Promise<boolean>;
  /** Default 90 days. Valid range: one hour to one year. */
  defaultTtlSeconds?: number;
}

interface StoredCredentialRow extends Record<string, unknown> {
  credential_id: unknown;
  organization_id: unknown;
  agent_id: unknown;
  key_prefix: unknown;
  allowed_actions: unknown;
  status: unknown;
  created_at: unknown;
  last_used_at: unknown;
  expires_at: unknown;
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required for credential hashing.");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function secureSecretPart(): string {
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new Error("A cryptographically secure random source is required for API keys.");
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? bytes[i + 1] : 0;
    const c = hasC ? bytes[i + 2] : 0;
    result += alphabet[(a >> 2) & 63];
    result += alphabet[((a & 3) << 4) | (b >> 4)];
    if (hasB) result += alphabet[((b & 15) << 2) | (c >> 6)];
    if (hasC) result += alphabet[c & 63];
  }
  return result;
}

function mapCredentialMetadata(row: StoredCredentialRow): AgentCredentialMetadata {
  const actions = stringArray(row.allowed_actions, "allowed_actions");
  if (!actions.every(isActionType)) throw new Error("Credential has an invalid action scope.");
  if (row.status !== "active" && row.status !== "revoked") {
    throw new Error("Credential has an invalid status.");
  }
  return {
    credentialId: nonEmptyString(row.credential_id, "credential_id"),
    organizationId: nonEmptyString(row.organization_id, "organization_id"),
    agentId: nonEmptyString(row.agent_id, "agent_id"),
    keyPrefix: nonEmptyString(row.key_prefix, "key_prefix"),
    allowedActions: actions as ActionType[],
    status: row.status,
    createdAt: toIso(row.created_at, "created_at"),
    lastUsedAt: row.last_used_at === null || row.last_used_at === undefined
      ? null : toIso(row.last_used_at, "last_used_at"),
    expiresAt: toIso(row.expires_at, "expires_at"),
  };
}

/**
 * API-key identity for server-to-server agent traffic.
 * Secrets are high-entropy, shown once and persisted only as SHA-256 digests.
 * The caller must protect every management method with its own authenticated server route.
 */
export function createPostgresAgentCredentialService(
  pool: PgPool,
  options: AgentCredentialServiceOptions,
) {
  if (!pool || typeof pool.query !== "function" || typeof pool.connect !== "function") {
    throw new Error("A compatible PostgreSQL pool is required.");
  }
  if (typeof options?.authorizeCredentialManagement !== "function") {
    throw new Error("A credential-management authorization callback is required.");
  }
  const defaultTtl = options.defaultTtlSeconds ?? 7776000;
  if (!Number.isInteger(defaultTtl) || defaultTtl < 3600 || defaultTtl > 31536000) {
    throw new Error("defaultTtlSeconds must be between one hour and one year.");
  }

  async function assertManager(organizationId: string, actorId: string): Promise<void> {
    if (!organizationId.trim() || !actorId.trim()
      || !await options.authorizeCredentialManagement({ organizationId, actorId })) {
      throw new Error("Credential management is not authorized for this organization.");
    }
  }

  async function writeCredentialAudit(
    client: PgConnection,
    input: {
      organizationId: string;
      credentialId: string;
      actorId: string;
      agentId: string;
      keyPrefix: string;
      action: "CREDENTIAL_CREATED" | "CREDENTIAL_REVOKED";
    },
  ): Promise<void> {
    await client.query(
      `INSERT INTO backstop_audit_events
         (occurred_at, organization_id, request_id, agent_id, tool_name, kind, decision,
          policy_version, action_type, resource, input_digest, reason)
       VALUES (now(),$1,$2,$3,$4,$5,'ALLOW','credential-service-v1',NULL,$6,NULL,$7)`,
      [
        input.organizationId,
        `credential:${input.credentialId}`,
        input.actorId,
        "credential.management",
        input.action,
        input.keyPrefix,
        input.action === "CREDENTIAL_CREATED"
          ? "An organization-scoped machine credential was created; the secret was disclosed once."
          : "An organization-scoped machine credential was revoked.",
      ],
    );
  }

  return {
    async create(input: {
      organizationId: string;
      actorId: string;
      agentId: string;
      allowedActions: readonly ActionType[];
      ttlSeconds?: number;
    }): Promise<CreatedAgentCredential> {
      if (!input || typeof input.organizationId !== "string" || typeof input.actorId !== "string"
        || typeof input.agentId !== "string" || !input.organizationId.trim()
        || !input.actorId.trim() || !input.agentId.trim()) {
        throw new Error("Organization, actor, and agent IDs are required.");
      }
      await assertManager(input.organizationId, input.actorId);
      if (!Array.isArray(input.allowedActions) || input.allowedActions.length === 0
        || !input.allowedActions.every(isActionType)) {
        throw new Error("At least one known action scope is required.");
      }
      const actions = [...new Set(input.allowedActions)];
      const ttlSeconds = input.ttlSeconds ?? defaultTtl;
      if (!Number.isInteger(ttlSeconds) || ttlSeconds < 3600 || ttlSeconds > 31536000) {
        throw new Error("Credential TTL must be between one hour and one year.");
      }

      const credentialId = globalThis.crypto?.randomUUID?.();
      if (!credentialId) throw new Error("A cryptographically secure UUID source is required.");
      const secret = `bsk_live_${secureSecretPart()}`;
      const keyPrefix = `bsk_live_${secret.slice("bsk_live_".length, "bsk_live_".length + 8)}`;
      const tokenHash = await sha256Hex(secret);
      const client = await pool.connect();
      let begun = false;
      try {
        await client.query("BEGIN");
        begun = true;
        const inserted = await client.query<StoredCredentialRow>(
          `INSERT INTO backstop_agent_credentials
             (credential_id, organization_id, agent_id, key_prefix, token_hash, allowed_actions,
              status, created_by, expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,'active',$7,now() + ($8 * interval '1 second'))
           RETURNING credential_id, organization_id, agent_id, key_prefix, allowed_actions,
                     status, created_at, last_used_at, expires_at`,
          [credentialId, input.organizationId, input.agentId, keyPrefix, tokenHash, actions, input.actorId, ttlSeconds],
        );
        const row = inserted.rows[0];
        if (!row) throw new Error("The database did not create the credential.");
        await writeCredentialAudit(client, {
          organizationId: input.organizationId,
          credentialId,
          actorId: input.actorId,
          agentId: input.agentId,
          keyPrefix,
          action: "CREDENTIAL_CREATED",
        });
        await client.query("COMMIT");
        begun = false;
        return { ...mapCredentialMetadata(row), secret };
      } catch (error) {
        if (begun) {
          try { await client.query("ROLLBACK"); } catch { /* Preserve the original failure. */ }
        }
        throw error;
      } finally {
        client.release();
      }
    },

    async authenticate(secret: string): Promise<AuthenticatedCredential | null> {
      if (typeof secret !== "string" || !/^bsk_live_[A-Za-z0-9_-]{43}$/.test(secret)) return null;
      const tokenHash = await sha256Hex(secret);
      const selected = await pool.query<StoredCredentialRow>(
        `SELECT credential_id, organization_id, agent_id, key_prefix, allowed_actions,
                status, created_at, last_used_at, expires_at
         FROM backstop_agent_credentials
         WHERE token_hash = $1 AND status = 'active' AND expires_at > now()`,
        [tokenHash],
      );
      const row = selected.rows[0];
      if (!row) return null;
      const metadata = mapCredentialMetadata(row);
      const touched = await pool.query<{ credential_id: unknown }>(
        `UPDATE backstop_agent_credentials
         SET last_used_at = now()
         WHERE credential_id = $1 AND status = 'active' AND expires_at > now()
         RETURNING credential_id`,
        [metadata.credentialId],
      );
      if (touched.rows.length !== 1) return null;
      return {
        credentialId: metadata.credentialId,
        agent: {
          id: metadata.agentId,
          organizationId: metadata.organizationId,
          allowedActions: metadata.allowedActions,
        },
      };
    },

    async list(input: { organizationId: string; actorId: string }): Promise<AgentCredentialMetadata[]> {
      if (!input || typeof input.organizationId !== "string" || typeof input.actorId !== "string") {
        throw new Error("Organization and actor are required.");
      }
      await assertManager(input.organizationId, input.actorId);
      const selected = await pool.query<StoredCredentialRow>(
        `SELECT credential_id, organization_id, agent_id, key_prefix, allowed_actions,
                status, created_at, last_used_at, expires_at
         FROM backstop_agent_credentials
         WHERE organization_id = $1
         ORDER BY created_at DESC, credential_id ASC`,
        [input.organizationId],
      );
      return selected.rows.map(mapCredentialMetadata);
    },

    async revoke(input: { organizationId: string; actorId: string; credentialId: string }): Promise<boolean> {
      if (!input || typeof input.organizationId !== "string" || typeof input.actorId !== "string"
        || typeof input.credentialId !== "string" || !input.credentialId.trim()) {
        throw new Error("Organization, actor, and credential IDs are required.");
      }
      await assertManager(input.organizationId, input.actorId);
      const client = await pool.connect();
      let begun = false;
      try {
        await client.query("BEGIN");
        begun = true;
        const selected = await client.query<StoredCredentialRow>(
          `SELECT credential_id, organization_id, agent_id, key_prefix, allowed_actions,
                  status, created_at, last_used_at, expires_at
           FROM backstop_agent_credentials
           WHERE organization_id = $1 AND credential_id = $2 AND status = 'active'
           FOR UPDATE`,
          [input.organizationId, input.credentialId],
        );
        const row = selected.rows[0];
        if (!row) {
          await client.query("COMMIT");
          begun = false;
          return false;
        }
        const metadata = mapCredentialMetadata(row);
        const updated = await client.query<{ credential_id: unknown }>(
          `UPDATE backstop_agent_credentials
           SET status = 'revoked', revoked_at = now()
           WHERE organization_id = $1 AND credential_id = $2 AND status = 'active'
           RETURNING credential_id`,
          [input.organizationId, input.credentialId],
        );
        if (updated.rows.length !== 1) throw new Error("Credential status changed before revocation completed.");
        await writeCredentialAudit(client, {
          organizationId: input.organizationId,
          credentialId: metadata.credentialId,
          actorId: input.actorId,
          agentId: metadata.agentId,
          keyPrefix: metadata.keyPrefix,
          action: "CREDENTIAL_REVOKED",
        });
        await client.query("COMMIT");
        begun = false;
        return true;
      } catch (error) {
        if (begun) {
          try { await client.query("ROLLBACK"); } catch { /* Preserve the original failure. */ }
        }
        throw error;
      } finally {
        client.release();
      }
    },
  };
}


export interface PostgresPolicyServiceOptions {
  /** Must authorize policy administrators from trusted organization membership data. */
  authorizePolicyManagement(input: { organizationId: string; actorId: string }): Promise<boolean>;
}

export interface PublishedPolicy {
  organizationId: string;
  version: string;
  rules: PolicyRule[];
  publishedAt: string;
}

function normalizePublishRules(rules: readonly PolicyRule[]): PolicyRule[] {
  if (!Array.isArray(rules) || rules.length > 200) {
    throw new Error("A policy must contain between 0 and 200 rules.");
  }
  const seenIds = new Set<string>();
  return rules.map((rule) => {
    if (!rule || typeof rule !== "object") throw new Error("Policy contains an invalid rule.");
    if (typeof rule.id !== "string" || !rule.id.trim() || rule.id.length > 120
      || seenIds.has(rule.id.trim())) {
      throw new Error("Policy rule IDs must be unique, non-empty, and at most 120 characters.");
    }
    seenIds.add(rule.id.trim());
    if (typeof rule.name !== "string" || !rule.name.trim() || rule.name.length > 200
      || typeof rule.description !== "string" || !rule.description.trim() || rule.description.length > 2000) {
      throw new Error("Policy rule name/description is missing or too long.");
    }
    if (rule.effect !== "BLOCK" && rule.effect !== "REQUIRE_APPROVAL") {
      throw new Error("Custom organization policies cannot grant ALLOW permissions.");
    }
    const rawActionTypes: unknown = rule.actionTypes;
    if (!Array.isArray(rawActionTypes) || rawActionTypes.length < 1 || rawActionTypes.length > ACTION_CATALOG.length
      || !rawActionTypes.every(isActionType)) {
      throw new Error("Policy rule contains an invalid action scope.");
    }
    const rawResources: unknown = rule.resources;
    if (!Array.isArray(rawResources) || rawResources.length < 1 || rawResources.length > 100
      || !rawResources.every((resource: unknown) =>
        typeof resource === "string" && !!resource.trim() && resource.length <= 1024)) {
      throw new Error("Policy rule contains invalid resource patterns.");
    }
    if (typeof rule.enabled !== "boolean" || typeof rule.priority !== "number"
      || !Number.isFinite(rule.priority) || Math.abs(rule.priority) > 1000000) {
      throw new Error("Policy rule contains an invalid enabled/priority setting.");
    }
    return {
      id: rule.id.trim(),
      name: rule.name.trim(),
      description: rule.description.trim(),
      effect: rule.effect,
      actionTypes: [...new Set(rawActionTypes as ActionType[])],
      resources: [...new Set((rawResources as string[]).map((resource: string) => resource.trim()))],
      enabled: rule.enabled,
      priority: Math.trunc(rule.priority),
      locked: false,
    };
  });
}

/**
 * Versioned PostgreSQL policy manager. Each publication is written in one transaction;
 * prior versions remain stored for inspection while the policy-set row points at the current one.
 */
export function createPostgresPolicyService(
  pool: PgPool,
  options: PostgresPolicyServiceOptions,
) {
  if (!pool || typeof pool.query !== "function" || typeof pool.connect !== "function") {
    throw new Error("A compatible PostgreSQL pool is required.");
  }
  if (typeof options?.authorizePolicyManagement !== "function") {
    throw new Error("A policy-management authorization callback is required.");
  }

  async function assertManager(organizationId: string, actorId: string): Promise<void> {
    if (!organizationId.trim() || !actorId.trim()
      || !await options.authorizePolicyManagement({ organizationId, actorId })) {
      throw new Error("Policy management is not authorized for this organization.");
    }
  }

  async function loadCurrent(organizationId: string): Promise<{ version: string; rules: PolicyRule[] }> {
    if (typeof organizationId !== "string" || !organizationId.trim()) {
      throw new Error("A trusted organization ID is required.");
    }
    // One statement gives a consistent version+rules snapshot even while an administrator publishes.
    const result = await pool.query<StoredRuleRow & { policy_version: unknown }>(
      `SELECT ps.policy_version, r.rule_id, r.name, r.description, r.effect,
              r.action_types, r.resource_patterns, r.enabled, r.priority
       FROM backstop_policy_sets ps
       LEFT JOIN backstop_policy_rules r
         ON r.organization_id = ps.organization_id AND r.policy_version = ps.policy_version
       WHERE ps.organization_id = $1
       ORDER BY r.priority DESC NULLS LAST, r.rule_id ASC NULLS LAST`,
      [organizationId],
    );
    if (result.rows.length === 0) return { version: "baseline", rules: [] };
    const version = nonEmptyString(result.rows[0].policy_version, "policy_version");
    const rules = result.rows
      .filter((row) => row.rule_id !== null && row.rule_id !== undefined)
      .map(mapPolicyRule);
    return { version, rules };
  }

  return {
    loadCurrent,

    async publish(input: {
      organizationId: string;
      actorId: string;
      rules: readonly PolicyRule[];
    }): Promise<PublishedPolicy> {
      if (!input || typeof input.organizationId !== "string" || typeof input.actorId !== "string"
        || !input.organizationId.trim() || !input.actorId.trim()) {
        throw new Error("Organization and actor IDs are required.");
      }
      await assertManager(input.organizationId, input.actorId);
      const rules = normalizePublishRules(input.rules);
      const revision = globalThis.crypto?.randomUUID?.();
      if (!revision) throw new Error("A cryptographically secure UUID source is required.");
      const version = `org_${revision.replaceAll("-", "")}`;
      const client = await pool.connect();
      let begun = false;
      const publishedAt = new Date().toISOString();
      try {
        await client.query("BEGIN");
        begun = true;
        await client.query(
          `INSERT INTO backstop_policy_sets (organization_id, policy_version, updated_at)
           VALUES ($1,$2,now())
           ON CONFLICT (organization_id) DO UPDATE
             SET policy_version = EXCLUDED.policy_version, updated_at = now()`,
          [input.organizationId, version],
        );
        for (const rule of rules) {
          await client.query(
            `INSERT INTO backstop_policy_rules
               (organization_id, policy_version, rule_id, name, description, effect, action_types,
                resource_patterns, enabled, priority)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [input.organizationId, version, rule.id, rule.name, rule.description, rule.effect,
              rule.actionTypes, rule.resources, rule.enabled, rule.priority],
          );
        }
        await client.query(
          `INSERT INTO backstop_audit_events
             (occurred_at, organization_id, request_id, agent_id, tool_name, kind, decision,
              policy_version, action_type, resource, input_digest, reason)
           VALUES (now(),$1,$2,$3,'policy.management','POLICY_PUBLISHED','ALLOW',$4,NULL,NULL,NULL,$5)`,
          [input.organizationId, `policy:${version}`, input.actorId, version,
            `Published policy ${version} with ${rules.length} restrictive custom rule(s).`],
        );
        await client.query("COMMIT");
        begun = false;
        return { organizationId: input.organizationId, version, rules, publishedAt: new Date().toISOString() };
      } catch (error) {
        if (begun) {
          try { await client.query("ROLLBACK"); } catch { /* Preserve the original failure. */ }
        }
        throw error;
      } finally {
        client.release();
      }
    },
  };
}
