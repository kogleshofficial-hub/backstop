/** Deterministic policy engine. This module never executes an operation. */
export const ACTION_CATALOG = [
  { type: "read_resource", label: "Read resource" }, { type: "search", label: "Search" },
  { type: "write_resource", label: "Write or update" }, { type: "send_external", label: "Send externally" },
  { type: "delete_resource", label: "Delete resource" }, { type: "transfer_funds", label: "Transfer funds" },
  { type: "change_permissions", label: "Change permissions" }, { type: "execute_code", label: "Execute code" },
  { type: "publish", label: "Publish" }
] as const;
export type ActionType = (typeof ACTION_CATALOG)[number]["type"];
export type Decision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
export interface ActionRequest { id: string; agent: string; actionType: ActionType; resource: string; summary: string; requestedAt?: string; }
export interface PolicyRule { id: string; name: string; description: string; effect: Decision; actionTypes: readonly ActionType[]; resources: readonly string[]; enabled: boolean; priority: number; locked?: boolean; }
export interface Evaluation { decision: Decision; reason: string; matchedRules: PolicyRule[]; policyVersion: string; }
export interface ApprovalRequest { id: string; status: "pending" | "approved" | "rejected"; reviewer?: string; reviewedAt?: string; resolution?: "approve" | "reject"; }
export const POLICY_VERSION = "backstop-baseline-1.0.1";
export const DEFAULT_RULES: readonly PolicyRule[] = [
 { id:"system-block-delete",name:"Block destructive deletion",description:"Destructive deletion is denied by the locked baseline.",effect:"BLOCK",actionTypes:["delete_resource"],resources:["*"],enabled:true,priority:1000,locked:true },
 { id:"system-block-transfer",name:"Block funds transfer",description:"Money movement is denied by the locked baseline.",effect:"BLOCK",actionTypes:["transfer_funds"],resources:["*"],enabled:true,priority:1000,locked:true },
 { id:"baseline-read",name:"Allow read-only operations",description:"Read and search requests may proceed, subject to the caller's own authentication and resource checks.",effect:"ALLOW",actionTypes:["read_resource","search"],resources:["*"],enabled:true,priority:100,locked:true },
 { id:"baseline-write",name:"Review writes and updates",description:"Changes to data or files pause until a human reviewer decides.",effect:"REQUIRE_APPROVAL",actionTypes:["write_resource"],resources:["*"],enabled:true,priority:200,locked:true },
 { id:"baseline-send",name:"Review external sends",description:"Messages and data leaving the workspace require review.",effect:"REQUIRE_APPROVAL",actionTypes:["send_external"],resources:["*"],enabled:true,priority:200,locked:true },
 { id:"baseline-permissions",name:"Review permission changes",description:"Role and access changes require review.",effect:"REQUIRE_APPROVAL",actionTypes:["change_permissions"],resources:["*"],enabled:true,priority:200,locked:true },
 { id:"baseline-code",name:"Review code execution",description:"Running code or shell commands requires review.",effect:"REQUIRE_APPROVAL",actionTypes:["execute_code"],resources:["*"],enabled:true,priority:200,locked:true },
 { id:"baseline-publish",name:"Review public releases",description:"Publishing content or releasing changes requires review.",effect:"REQUIRE_APPROVAL",actionTypes:["publish"],resources:["*"],enabled:true,priority:200,locked:true }
] as const;
const knownActions = new Set<string>(ACTION_CATALOG.map((x) => x.type));
const hardBlocked = new Set<ActionType>(["delete_resource","transfer_funds"]);
const weight: Record<Decision, number> = { BLOCK:3, REQUIRE_APPROVAL:2, ALLOW:1 };
function isActionType(value: unknown): value is ActionType { return typeof value === "string" && knownActions.has(value); }
function matchesResource(pattern: string, resource: string): boolean {
 const p=pattern.trim().toLowerCase(), r=resource.trim().toLowerCase();
 if(p==="*") return true;
 if(p.endsWith("/**")) { const prefix=p.slice(0,-3); return r===prefix || r.startsWith(prefix+"/"); }
 return p===r;
}
function matchesRule(rule: PolicyRule, request: ActionRequest): boolean {
 return rule.enabled && rule.actionTypes.includes(request.actionType) && rule.resources.some((pattern)=>matchesResource(pattern,request.resource));
}
function isValidCustomRule(value: unknown): value is PolicyRule {
 if (!value || typeof value !== "object") return false;
 const rule = value as Partial<PolicyRule>;
 return typeof rule.id === "string" && !!rule.id.trim()
  && typeof rule.name === "string" && !!rule.name.trim()
  && typeof rule.description === "string" && !!rule.description.trim()
  && (rule.effect === "BLOCK" || rule.effect === "REQUIRE_APPROVAL")
  && Array.isArray(rule.actionTypes) && rule.actionTypes.length > 0 && rule.actionTypes.every(isActionType)
  && Array.isArray(rule.resources) && rule.resources.length > 0
  && rule.resources.every((resource) => typeof resource === "string" && !!resource.trim())
  && typeof rule.enabled === "boolean" && typeof rule.priority === "number" && Number.isFinite(rule.priority);
}
function requireReview(reason: string): Evaluation {
 return {decision:"REQUIRE_APPROVAL",reason,matchedRules:[],policyVersion:POLICY_VERSION};
}
export function evaluateAction(request: ActionRequest, customRules: readonly PolicyRule[] = []): Evaluation {
 if(!request || typeof request.id!=="string" || !request.id.trim() || typeof request.agent!=="string" || !request.agent.trim() || typeof request.resource!=="string" || !request.resource.trim() || typeof request.summary!=="string" || !request.summary.trim() || !isActionType(request.actionType))
  return requireReview("The request is incomplete or uses an unknown operation. Review before execution.");
 // Immutable baseline prohibitions take precedence over all caller-supplied policy.
 if(hardBlocked.has(request.actionType)) {
  const rule=DEFAULT_RULES.find((candidate)=>candidate.actionTypes.includes(request.actionType)&&candidate.locked);
  return {decision:"BLOCK",reason:rule?.description??"Denied by baseline safety invariant.",matchedRules:rule?[rule]:[],policyVersion:POLICY_VERSION};
 }
 // Treat externally supplied policy as untrusted configuration. An invalid or permissive
 // custom rule must never silently weaken the baseline or turn an unknown state into ALLOW.
 if(!Array.isArray(customRules) || !customRules.every(isValidCustomRule))
  return requireReview("Policy configuration is invalid or attempts to grant permissions. Review the policy before execution.");
 const matches=[...DEFAULT_RULES,...customRules].filter((rule)=>matchesRule(rule,request)).sort((a,b)=>weight[b.effect]-weight[a.effect]||b.priority-a.priority);
 if(!matches.length) return requireReview("No enabled policy matched. Backstop defaults to human review.");
 return {decision:matches[0].effect,reason:matches[0].description,matchedRules:matches,policyVersion:POLICY_VERSION};
}
export function resolveApproval<T extends ApprovalRequest>(request:T,outcome:"approve"|"reject",reviewer:string,reviewedAt=new Date().toISOString()):T {
 if(request.status!=="pending") throw new Error("Only pending requests can be resolved.");
 if(!reviewer.trim()) throw new Error("A reviewer identity is required.");
 return {...request,status:outcome==="approve"?"approved":"rejected",resolution:outcome,reviewer,reviewedAt};
}
/** User-created rules deliberately cannot grant permissions. */
export function createRestriction(input:{id:string;name:string;description:string;effect:Exclude<Decision,"ALLOW">;actionType:ActionType;resourcePattern:string;priority?:number}):PolicyRule {
 if((input.effect as string)!=="BLOCK" && (input.effect as string)!=="REQUIRE_APPROVAL") throw new Error("Custom rules may only block or require approval.");
 if(!input.id.trim()||!input.name.trim()||!input.description.trim()||!input.resourcePattern.trim()) throw new Error("Rule id, name, reason, and resource pattern are required.");
 if(!isActionType(input.actionType)) throw new Error("Unknown action type.");
 return {id:input.id.trim(),name:input.name.trim(),description:input.description.trim(),effect:input.effect,actionTypes:[input.actionType],resources:[input.resourcePattern.trim()],enabled:true,priority:input.priority??300,locked:false};
}
