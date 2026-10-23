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

export interface GuardedToolContext {
  agent: AuthenticatedAgent;
  request: ActionRequest;
  evaluation: Evaluation;
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
    | "EXECUTION_AUTHORIZED"
    | "EXECUTION_SUCCEEDED"
    | "EXECUTION_FAILED"
    | "GATE_ERROR";
  decision: Decision | null;
  policyVersion: string;
  actionType?: ActionType;
  resource?: string;
  reason: string;
}

export interface ExecutionGateDependencies {
  /** Resolve only policy rules loaded from a trusted policy store for this organization. */
  getRules(agent: AuthenticatedAgent): Promise<readonly PolicyRule[]>;
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
   * Verify a durable, unexpired approval that is bound to this exact request and organization.
   * Validate reviewer permissions, approval status, request/payload digest, expiry and replay state
   * in your trusted store. Returning true is a security-sensitive decision.
   */
  verifyApproval(input: {
    agent: AuthenticatedAgent;
    request: ActionRequest;
    approval: ApprovalEvidence;
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
  | { status: "executed"; request: ActionRequest; evaluation: Evaluation; output: TOutput; auditComplete: boolean }
  | { status: "blocked"; request?: ActionRequest; evaluation?: Evaluation; reason: string }
  | { status: "approval_required"; request: ActionRequest; evaluation: Evaluation; reason: string }
  | { status: "execution_failed"; request: ActionRequest; evaluation: Evaluation; auditComplete: boolean; reason: string }
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

      let request: ActionRequest | undefined;
      let evaluation: Evaluation | undefined;

      try {
        const parsed = tool.parseInput(input.input);
        const safeInput = snapshotJson(parsed);
        const description = tool.describe(safeInput, input.agent);

        if (!safeText(description?.resource, 4096) || !safeText(description?.summary, 1024)) {
          throw new Error("Tool resource and summary must be safe, non-empty text.");
        }

        request = {
          id: input.requestId,
          agent: input.agent.id,
          actionType: tool.actionType,
          resource: description.resource,
          summary: description.summary,
          requestedAt: new Date().toISOString(),
        };

        if (!input.agent.allowedActions.includes(tool.actionType)) {
          evaluation = buildEvaluation("BLOCK", "The authenticated agent is not permitted to use this action type.");
        } else {
          const authorized = await dependencies.authorizeResource({
            agent: input.agent,
            actionType: tool.actionType,
            resource: request.resource,
          });
          if (!authorized) {
            evaluation = buildEvaluation("BLOCK", "The authenticated agent is not authorized for this resource.");
          } else {
            const rules = await dependencies.getRules(input.agent);
            evaluation = evaluateAction(request, rules);
          }
        }

        if (evaluation.decision === "BLOCK") {
          const logged = await appendAudit({
            requestId: request.id, organizationId: input.agent.organizationId, agentId: input.agent.id,
            toolName: tool.name, kind: "BLOCKED", decision: evaluation.decision,
            actionType: request.actionType, resource: request.resource, reason: evaluation.reason,
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
              verified = await dependencies.verifyApproval({ agent: input.agent, request, approval: input.approval });
            } catch {
              verified = false;
            }
          }

          if (!verified) {
            const reason = "A valid, unexpired approval bound to this exact request is required.";
            const logged = await appendAudit({
              requestId: request.id, organizationId: input.agent.organizationId, agentId: input.agent.id,
              toolName: tool.name, kind: "APPROVAL_REQUIRED", decision: evaluation.decision,
              actionType: request.actionType, resource: request.resource, reason,
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
          requestId: request.id, organizationId: input.agent.organizationId, agentId: input.agent.id,
          toolName: tool.name, kind: "EXECUTION_AUTHORIZED", decision: evaluation.decision,
          actionType: request.actionType, resource: request.resource, reason: evaluation.reason,
          policyVersion: evaluation.policyVersion,
        });
        if (!startLogged) {
          return { status: "error", request, evaluation, reason: "Audit storage is unavailable. No action was executed." };
        }

        let output: TOutput;
        try {
          output = await tool.execute(safeInput, { agent: input.agent, request, evaluation }) as TOutput;
        } catch {
          const completedLog = await appendAudit({
            requestId: request.id, organizationId: input.agent.organizationId, agentId: input.agent.id,
            toolName: tool.name, kind: "EXECUTION_FAILED", decision: evaluation.decision,
            actionType: request.actionType, resource: request.resource,
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
          requestId: request.id, organizationId: input.agent.organizationId, agentId: input.agent.id,
          toolName: tool.name, kind: "EXECUTION_SUCCEEDED", decision: evaluation.decision,
          actionType: request.actionType, resource: request.resource,
          reason: "The registered tool completed successfully.", policyVersion: evaluation.policyVersion,
        });
        return { status: "executed", request, evaluation, output, auditComplete: completedLog };
      } catch {
        const logged = await appendAudit({
          requestId: input.requestId, organizationId: input.agent.organizationId, agentId: input.agent.id,
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
