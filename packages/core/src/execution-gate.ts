import {
  ACTION_CATALOG,
  POLICY_VERSION,
  evaluateAction,
  type ActionRequest,
  type ActionType,
  type Decision,
  type Evaluation,
  type PolicyRule,
} from "./index.js";

/**
 * This principal must be created by trusted server-side authentication middleware.
 * Never construct it from fields supplied in an HTTP request body.
 */
export interface AuthenticatedAgent {
  id: string;
  organizationId: string;
  allowedActions: readonly ActionType[];
}

export interface ApprovalEvidence {
  requestId: string;
  approvalId: string;
}

export interface GuardedActionRequest extends ActionRequest {
  /** Fixed by the server-registered tool definition, never the request body. */
  toolName: string;
  /** SHA-256 of canonical JSON input; approval must be bound to this exact payload. */
  inputDigest: string;
  /** Evaluator + organization policy revision that authorized or reviewed the action. */
  policyVersion: string;
}

export interface GuardedToolContext {
  agent: AuthenticatedAgent;
  request: GuardedActionRequest;
  evaluation: Evaluation;
  inputDigest: string;
}

export interface GuardedTool<TInput = unknown, TOutput = unknown> {
  /** Stable server-registered tool name. Never register tools directly from user input. */
  name: string;
  /** The action type is fixed by trusted server-side registration, not by the client. */
  actionType: ActionType;
  /**
   * Validate and return a detached, canonical representation of input.
   * The gate snapshots and freezes JSON-compatible values before evaluation/execution.
   */
  parseInput(input: unknown): TInput;
  /** Derive the exact logical resource and a safe, concise audit summary. */
  describe(input: TInput, agent: AuthenticatedAgent): { resource: string; summary: string };
  /**
   * Execute this exact registered operation only. The input is the same immutable
   * snapshot used by describe(); adapters must not silently target another resource.
   */
  execute(input: TInput, context: GuardedToolContext): Promise<TOutput> | TOutput;
}

/** Internal heterogeneous registry type; callers should register typed GuardedTool values. */
type RegisteredTool = GuardedTool<any, any>;

export interface GateAuditEvent {
  occurredAt: string;
  requestId: string;
  organizationId: string;
  agentId: string;
  toolName: string;
  kind:
    | "BLOCKED"
    | "APPROVAL_REQUIRED"
    | "APPROVAL_APPROVED"
    | "APPROVAL_REJECTED"
    | "CREDENTIAL_CREATED"
    | "CREDENTIAL_REVOKED"
    | "EXECUTION_AUTHORIZED"
    | "EXECUTION_SUCCEEDED"
    | "EXECUTION_FAILED"
    | "GATE_ERROR";
  decision: Decision | null;
  policyVersion: string;
  actionType?: ActionType;
  resource?: string;
  inputDigest?: string;
  reason: string;
}

export interface ExecutionGateDependencies {
  /** Resolve a consistent, trusted policy snapshot for this organization. */
  getRules(agent: AuthenticatedAgent): Promise<{ version: string; rules: readonly PolicyRule[] }>;
  /**
   * Enforce app-specific object/tenant ACLs. This is required even when policy says ALLOW.
   * It must use the authenticated agent and canonical resource; it must not trust client claims.
   */
  authorizeResource(input: {
    agent: AuthenticatedAgent;
    actionType: ActionType;
    resource: string;
  }): Promise<boolean>;
  /**
   * Atomically validate AND consume a durable, unexpired approval bound to this request,
   * organization and input digest. Check reviewer rights and prevent concurrent replay in the
   * trusted store (for example, using a transaction that changes pending -> consumed only once).
   * A read-only "is approved" check is not sufficient. Returning true authorizes execution.
   */
  verifyAndConsumeApproval(input: {
    agent: AuthenticatedAgent;
    request: GuardedActionRequest;
    inputDigest: string;
    approval: ApprovalEvidence;
  }): Promise<boolean>;
  /**
   * Persist a request that requires human review. This must be idempotent by organization + request
   * ID, refuse conflicting input digests, and retain the exact action/policy metadata for review.
   */
  recordApprovalRequest(input: {
    agent: AuthenticatedAgent;
    request: GuardedActionRequest;
    evaluation: Evaluation;
  }): Promise<void>;
  /**
   * Atomically claim a one-time execution slot keyed by organizationId + request.id.
   * Persist the inputDigest and refuse existing/in-progress/completed IDs, including a reused
   * ID paired with a different digest. This must be backed by a durable unique constraint or
   * transaction, not an in-memory Set; throw on storage failure so the gate fails closed.
   */
  claimExecution(input: {
    agent: AuthenticatedAgent;
    request: GuardedActionRequest;
    toolName: string;
  }): Promise<boolean>;
  /** Append to server-controlled audit storage. Do not implement this with browser localStorage. */
  appendAudit(event: GateAuditEvent): Promise<void>;
}

export interface InvokeGuardedToolInput {
  /** Server-generated ID for this exact proposed action; persist it with approval requests. */
  requestId: string;
  /** Principal returned by trusted server authentication middleware. */
  agent: AuthenticatedAgent;
  toolName: string;
  input: unknown;
  approval?: ApprovalEvidence;
}

export type ExecutionGateResult<TOutput = unknown> =
  | { status: "executed"; request: GuardedActionRequest; evaluation: Evaluation; output: TOutput; auditComplete: boolean }
  | { status: "blocked"; request?: GuardedActionRequest; evaluation?: Evaluation; reason: string }
  | { status: "approval_required"; request: GuardedActionRequest; evaluation: Evaluation; reason: string }
  | { status: "execution_failed"; request: GuardedActionRequest; evaluation: Evaluation; auditComplete: boolean; reason: string }
  | { status: "error"; request?: ActionRequest; evaluation?: Evaluation; reason: string };

const knownActions = new Set<string>(ACTION_CATALOG.map((action) => action.type));
const unsafeKeys = new Set(["__proto__", "prototype", "constructor"]);
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

function safeText(value: unknown, maximum: number): value is string {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= maximum
    && !CONTROL_CHARS.test(value);
}

function isAuthenticatedAgent(value: unknown): value is AuthenticatedAgent {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AuthenticatedAgent>;
  return safeText(candidate.id, 200)
    && safeText(candidate.organizationId, 200)
    && Array.isArray(candidate.allowedActions)
    && candidate.allowedActions.every((action) => typeof action === "string" && knownActions.has(action));
}

/**
 * Produce an immutable JSON-only snapshot to reduce mutation and prototype-pollution risks
 * while a request awaits policy, ACL, approval and audit storage calls.
 */
function snapshotJson(value: unknown, ancestors = new WeakSet<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object") throw new Error("Tool input must be JSON-compatible.");

  const object = value as object;
  if (ancestors.has(object)) throw new Error("Tool input must not contain cycles.");
  ancestors.add(object);

  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^\d+$/.test(key)))) {
      throw new Error("Tool input arrays cannot contain custom properties.");
    }
    const result: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new Error("Tool input arrays must be dense data arrays.");
      }
      result.push(snapshotJson(descriptor.value, ancestors));
    }
    ancestors.delete(object);
    return Object.freeze(result);
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("Tool input must contain only plain JSON objects.");
  }

  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || unsafeKeys.has(key)) {
      throw new Error("Tool input contains an unsupported property name.");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("Tool input must not contain accessors or non-enumerable properties.");
    }
    result[key] = snapshotJson(descriptor.value, ancestors);
  }
  ancestors.delete(object);
  return Object.freeze(result);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Value cannot be encoded as JSON.");
    return encoded;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Value cannot be encoded as JSON.");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object" && value !== null) {
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonicalJson(object[key])).join(",") + "}";
  }
  throw new Error("Tool input cannot be canonicalized as JSON.");
}

async function sha256Json(value: unknown): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required to bind approvals to action input.");
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buildEvaluation(
  decision: Decision,
  reason: string,
  policyVersion = POLICY_VERSION,
): Evaluation {
  return { decision, reason, matchedRules: [], policyVersion };
}

function isRequestId(value: unknown): value is string {
  return safeText(value, 128) && !/[\r\n]/.test(value);
}

export function createExecutionGate(
  tools: readonly RegisteredTool[],
  dependencies: ExecutionGateDependencies,
) {
  const registry = new Map<string, RegisteredTool>();

  for (const tool of tools) {
    if (!safeText(tool.name, 120) || registry.has(tool.name)) {
      throw new Error("Guarded tool names must be unique, non-empty, and at most 120 characters.");
    }
    if (!knownActions.has(tool.actionType)) {
      throw new Error("A guarded tool must use a known action type.");
    }
    registry.set(tool.name, tool);
  }

  async function appendAudit(event: Omit<GateAuditEvent, "occurredAt" | "policyVersion"> & { policyVersion?: string }): Promise<boolean> {
    try {
      await dependencies.appendAudit({
        ...event,
        occurredAt: new Date().toISOString(),
        policyVersion: event.policyVersion ?? POLICY_VERSION,
      });
      return true;
    } catch {
      return false;
    }
  }

  return {
    async invoke<TOutput = unknown>(
      input: InvokeGuardedToolInput,
    ): Promise<ExecutionGateResult<TOutput>> {
      if (!input || !isRequestId(input.requestId) || !isAuthenticatedAgent(input.agent)) {
        return {
          status: "error",
          reason: "A valid server-generated request ID and authenticated agent context are required. No action was executed.",
        };
      }

      const tool = registry.get(input.toolName);
      if (!tool) {
        const logged = await appendAudit({
          requestId: input.requestId,
          organizationId: input.agent.organizationId,
          agentId: input.agent.id,
          toolName: safeText(input.toolName, 120) ? input.toolName : "unknown",
          kind: "BLOCKED",
          decision: "BLOCK",
          reason: "The requested tool is not registered on this server.",
        });
        return logged
          ? { status: "blocked", evaluation: buildEvaluation("BLOCK", "The requested tool is not registered on this server."), reason: "Unknown tool. No action was executed." }
          : { status: "error", reason: "Audit storage is unavailable. No action was executed." };
      }

      const agent: AuthenticatedAgent = Object.freeze({
        id: input.agent.id,
        organizationId: input.agent.organizationId,
        allowedActions: Object.freeze([...input.agent.allowedActions]),
      });

      let request: GuardedActionRequest | undefined;
      let inputDigest: string | undefined;
      let evaluation: Evaluation | undefined;

      try {
        const parsed = tool.parseInput(input.input);
        const safeInput = snapshotJson(parsed);
        inputDigest = await sha256Json(safeInput);
        const description = tool.describe(safeInput, agent);

        if (!safeText(description?.resource, 4096) || !safeText(description?.summary, 1024)) {
          throw new Error("Tool resource and summary must be safe, non-empty text.");
        }

        request = {
          id: input.requestId,
          agent: agent.id,
          inputDigest,
          toolName: tool.name,
          policyVersion: POLICY_VERSION,
          actionType: tool.actionType,
          resource: description.resource,
          summary: description.summary,
          requestedAt: new Date().toISOString(),
        };

        if (!agent.allowedActions.includes(tool.actionType)) {
          evaluation = buildEvaluation("BLOCK", "The authenticated agent is not permitted to use this action type.");
        } else {
          const authorized = await dependencies.authorizeResource({
            agent: agent,
            actionType: tool.actionType,
            resource: request.resource,
          });
          if (!authorized) {
            evaluation = buildEvaluation("BLOCK", "The authenticated agent is not authorized for this resource.");
          } else {
            const policy = await dependencies.getRules(agent);
            if (!policy || !safeText(policy.version, 120) || !Array.isArray(policy.rules)) {
              evaluation = buildEvaluation("BLOCK", "The trusted organization policy snapshot is invalid. Restore a valid policy before execution.");
            } else {
              const evaluated = evaluateAction(request, policy.rules);
              evaluation = {
                ...evaluated,
                policyVersion: `${POLICY_VERSION};org=${policy.version}`,
              };
            }
          }
        }

        request = Object.freeze({ ...request, policyVersion: evaluation.policyVersion });

        if (evaluation.decision === "BLOCK") {
          const logged = await appendAudit({
            requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
            toolName: tool.name, kind: "BLOCKED", decision: evaluation.decision,
            actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest, reason: evaluation.reason,
            policyVersion: evaluation.policyVersion,
          });
          return logged
            ? { status: "blocked", request, evaluation, reason: evaluation.reason }
            : { status: "error", request, evaluation, reason: "Audit storage is unavailable. No action was executed." };
        }

        if (evaluation.decision === "REQUIRE_APPROVAL") {
          let verified = false;
          if (input.approval && input.approval.requestId === request.id && safeText(input.approval.approvalId, 256)) {
            try {
              verified = await dependencies.verifyAndConsumeApproval({ agent, request, inputDigest: request.inputDigest, approval: input.approval });
            } catch {
              verified = false;
            }
          }

          if (!verified) {
            const reason = "A valid, unexpired approval bound to this exact request is required.";
            try {
              await dependencies.recordApprovalRequest({ agent, request, evaluation });
            } catch {
              const queueReason = "The durable approval-request store is unavailable. No action was executed.";
              await appendAudit({
                requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
                toolName: tool.name, kind: "GATE_ERROR", decision: evaluation.decision,
                actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest,
                reason: queueReason, policyVersion: evaluation.policyVersion,
              });
              return { status: "error", request, evaluation, reason: queueReason };
            }
            const logged = await appendAudit({
              requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
              toolName: tool.name, kind: "APPROVAL_REQUIRED", decision: evaluation.decision,
              actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest, reason,
              policyVersion: evaluation.policyVersion,
            });
            return logged
              ? { status: "approval_required", request, evaluation, reason }
              : { status: "error", request, evaluation, reason: "Audit storage is unavailable. No action was executed." };
          }

          evaluation = {
            ...evaluation,
            decision: "ALLOW",
            reason: "A trusted approval verifier confirmed authorization for this exact request.",
          };
        }

        const startLogged = await appendAudit({
          requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
          toolName: tool.name, kind: "EXECUTION_AUTHORIZED", decision: evaluation.decision,
          actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest, reason: evaluation.reason,
          policyVersion: evaluation.policyVersion,
        });
        if (!startLogged) {
          return { status: "error", request, evaluation, reason: "Audit storage is unavailable. No action was executed." };
        }

        let claimed = false;
        try {
          claimed = await dependencies.claimExecution({ agent, request, toolName: tool.name });
        } catch {
          const reason = "The durable execution-claim store is unavailable. No action was executed.";
          await appendAudit({
            requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
            toolName: tool.name, kind: "GATE_ERROR", decision: "BLOCK",
            actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest,
            reason, policyVersion: evaluation.policyVersion,
          });
          return { status: "error", request, evaluation, reason };
        }

        if (!claimed) {
          const reason = "This request ID was already claimed or conflicts with an earlier payload. No action was executed.";
          const logged = await appendAudit({
            requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
            toolName: tool.name, kind: "BLOCKED", decision: "BLOCK",
            actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest,
            reason, policyVersion: evaluation.policyVersion,
          });
          return logged
            ? { status: "blocked", request, evaluation: buildEvaluation("BLOCK", reason, evaluation.policyVersion), reason }
            : { status: "error", request, evaluation, reason: "Duplicate execution was refused, but audit storage is unavailable." };
        }

        let output: TOutput;
        try {
          output = await tool.execute(safeInput, { agent, request, evaluation, inputDigest: request.inputDigest }) as TOutput;
        } catch {
          const completedLog = await appendAudit({
            requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
            toolName: tool.name, kind: "EXECUTION_FAILED", decision: evaluation.decision,
            actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest,
            reason: "The registered tool execution failed.", policyVersion: evaluation.policyVersion,
          });
          return {
            status: "execution_failed", request, evaluation, auditComplete: completedLog,
            reason: completedLog
              ? "The registered tool failed. Check the tool's server-side logs."
              : "The tool failed and audit storage could not record the failure.",
          };
        }

        const completedLog = await appendAudit({
          requestId: request.id, organizationId: agent.organizationId, agentId: agent.id,
          toolName: tool.name, kind: "EXECUTION_SUCCEEDED", decision: evaluation.decision,
          actionType: request.actionType, resource: request.resource, inputDigest: request.inputDigest,
          reason: "The registered tool completed successfully.", policyVersion: evaluation.policyVersion,
        });
        return { status: "executed", request, evaluation, output, auditComplete: completedLog };
      } catch {
        const logged = await appendAudit({
          requestId: input.requestId, organizationId: agent.organizationId, agentId: agent.id,
          toolName: tool.name, kind: "GATE_ERROR", decision: evaluation?.decision ?? null,
          actionType: request?.actionType, resource: request?.resource,
          reason: "The gate could not validate or authorize this request. No action was executed.",
          policyVersion: evaluation?.policyVersion ?? POLICY_VERSION,
        });
        return {
          status: "error", request, evaluation,
          reason: logged
            ? "The gate could not validate or authorize this request. No action was executed."
            : "The gate or audit storage failed. No action was executed.",
        };
      }
    },
  };
}
