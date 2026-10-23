import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  Activity, AlertTriangle, ArrowRight, Check, CheckCheck, ChevronDown, CircleHelp,
  Clock3, Code2, Copy, Download, ExternalLink, FileCheck2, Fingerprint, Github,
  Globe2, History, LayoutDashboard, LockKeyhole, Menu, Plus, Search, Settings2,
  Shield, ShieldAlert, ShieldCheck, ShieldX, Terminal, Trash2, X, type LucideIcon
} from "lucide-react";
import {
  ACTION_CATALOG, DEFAULT_RULES, POLICY_VERSION, createRestriction, evaluateAction,
  resolveApproval, type ActionType, type Decision, type PolicyRule
} from "@backstop/core";

type Page = "overview" | "requests" | "policies" | "audit" | "developer";
type RequestStatus = "allowed" | "blocked" | "pending" | "approved" | "rejected";
type EventKind = "ALLOW" | "BLOCK" | "REVIEW" | "APPROVED" | "REJECTED" | "POLICY";
interface Proposal {
  id: string; agent: string; actionType: ActionType; resource: string; summary: string;
  requestedAt: string; decision: Decision; status: RequestStatus; reason: string;
  matchedRule: string; reviewedAt?: string; reviewer?: string;
}
interface AuditEvent { id: string; at: string; actor: string; kind: EventKind; title: string; detail: string; }
const KEYS = { proposals: "backstop.v1.proposals", audit: "backstop.v1.audit", rules: "backstop.v1.rules" };
const SNIPPET = `import { Pool } from "pg";
import { createExecutionGate } from "@backstop/core/execution-gate";
import { createPostgresExecutionGateDependencies } from "@backstop/core/postgres-adapter";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Implement these with your real authenticated identity and object-level ACL.
const dependencies = createPostgresExecutionGateDependencies(pool, {
  authorizeResource: ({ agent, actionType, resource }) =>
    appAcl.canInvoke(agent.id, agent.organizationId, actionType, resource),
  authorizeReviewer: ({ organizationId, reviewerId }) =>
    membershipStore.canReviewAIApprovals(organizationId, reviewerId),
});

const gate = createExecutionGate(serverRegisteredTools, dependencies);

// Run inside an authenticated server route, never browser code.
const result = await gate.invoke({
  requestId: crypto.randomUUID(),
  agent: authenticatedAgent,
  toolName: "documents.read",
  input: validatedBody,
});

if (result.status === "approval_required") {
  return Response.json({ requestId: result.request.id, decision: "REQUIRE_APPROVAL" }, { status: 202 });
}
if (result.status === "blocked") {
  return Response.json({ error: result.reason }, { status: 403 });
}
if (result.status !== "executed") {
  return Response.json({ error: result.reason }, { status: 500 });
}
return Response.json({ output: result.output });`;
const NAV: { id: Page; label: string; icon: LucideIcon; group: string }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, group: "CONTROL" },
  { id: "requests", label: "Action requests", icon: Activity, group: "CONTROL" },
  { id: "policies", label: "Policies", icon: ShieldCheck, group: "GOVERNANCE" },
  { id: "audit", label: "Audit log", icon: History, group: "GOVERNANCE" },
  { id: "developer", label: "Developer", icon: Code2, group: "BUILD" }
];

function id(prefix: string) {
  return prefix + "_" + (typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2, 9));
}
function stored<T>(key: string, fallback: T): T {
  try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) as T : fallback; }
  catch { return fallback; }
}
function usePersisted<T>(key: string, initial: T): [T, (value: T | ((current: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => stored(key, initial));
  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* optional storage */ } }, [key, value]);
  return [value, setValue];
}
function labelFor(type: ActionType) { return ACTION_CATALOG.find((item) => item.type === type)?.label ?? type; }
function dateLabel(value: string) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "Unknown time" : new Intl.DateTimeFormat("en-MY", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(d);
}
function ago(value: string) {
  const delta = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(delta)) return "—";
  if (delta < 60_000) return "just now";
  if (delta < 3_600_000) return Math.floor(delta / 60_000) + "m ago";
  if (delta < 86_400_000) return Math.floor(delta / 3_600_000) + "h ago";
  return Math.floor(delta / 86_400_000) + "d ago";
}
function statusLabel(status: RequestStatus) {
  return ({ allowed: "Allowed", blocked: "Blocked", pending: "Needs review", approved: "Approved", rejected: "Rejected" })[status];
}
function seedDemo(): { proposals: Proposal[]; events: AuditEvent[] } {
  const old = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
  const proposals: Proposal[] = [
    { id: "req_demo_1058", agent: "support-agent", actionType: "read_resource", resource: "workspace/quarterly-report.md", summary: "Summarize the quarterly workspace report.", requestedAt: old(8), decision: "ALLOW", status: "allowed", reason: "Read-only actions are allowed by the baseline, subject to caller authentication and resource checks.", matchedRule: "Allow read-only operations" },
    { id: "req_demo_1057", agent: "research-agent", actionType: "write_resource", resource: "workspace/launch-plan.md", summary: "Update the public launch plan with draft messaging.", requestedAt: old(17), decision: "REQUIRE_APPROVAL", status: "pending", reason: "Changes to data or files pause until a human reviewer decides.", matchedRule: "Review writes and updates" },
    { id: "req_demo_1056", agent: "ops-agent", actionType: "delete_resource", resource: "production/customer-records/*", summary: "Remove a set of customer records.", requestedAt: old(29), decision: "BLOCK", status: "blocked", reason: "Destructive deletion is denied by the locked baseline.", matchedRule: "Block destructive deletion" },
    { id: "req_demo_1055", agent: "support-agent", actionType: "send_external", resource: "email/customer-export.csv", summary: "Send an export to an external recipient.", requestedAt: old(43), decision: "REQUIRE_APPROVAL", status: "pending", reason: "Messages and data leaving the workspace require review.", matchedRule: "Review external sends" },
    { id: "req_demo_1054", agent: "admin-agent", actionType: "change_permissions", resource: "workspace/finance", summary: "Grant another agent access to the finance workspace.", requestedAt: old(85), decision: "REQUIRE_APPROVAL", status: "rejected", reason: "Role and access changes require review.", matchedRule: "Review permission changes", reviewer: "workspace.operator", reviewedAt: old(78) }
  ];
  const events: AuditEvent[] = [
    { id: "evt_demo_1", at: old(8), actor: "support-agent", kind: "ALLOW", title: "Read request allowed", detail: "quarterly-report.md matched the read-only baseline." },
    { id: "evt_demo_2", at: old(17), actor: "research-agent", kind: "REVIEW", title: "Approval requested", detail: "Launch plan update is waiting for a reviewer." },
    { id: "evt_demo_3", at: old(29), actor: "ops-agent", kind: "BLOCK", title: "Destructive action blocked", detail: "Customer record deletion matched a locked baseline rule." },
    { id: "evt_demo_4", at: old(43), actor: "support-agent", kind: "REVIEW", title: "External send paused", detail: "A reviewer must approve the outbound export." },
    { id: "evt_demo_5", at: old(78), actor: "workspace.operator", kind: "REJECTED", title: "Permission request rejected", detail: "Finance workspace access was rejected by the reviewer." }
  ];
  return { proposals, events };
}
function Badge({ status }: { status: RequestStatus }) {
  const Icon = status === "allowed" || status === "approved" ? Check : status === "blocked" ? ShieldX : status === "pending" ? Clock3 : X;
  return <span className={"status s-" + status}><Icon size={12} />{statusLabel(status)}</span>;
}
function Metric({ icon: Icon, label, value, caption, tone }: { icon: LucideIcon; label: string; value: number; caption: string; tone: string }) {
  return <article className={"metric tone-" + tone}><div className="metric-label">{label}<span><Icon size={16} /></span></div><div className="metric-value">{value}</div><div className="metric-caption"><i />{caption}</div></article>;
}
function Empty({ icon: Icon, title, text }: { icon: LucideIcon; title: string; text: string }) {
  return <div className="empty"><div><Icon size={21} /></div><strong>{title}</strong><p>{text}</p></div>;
}
function EventIcon({ kind }: { kind: EventKind }) {
  if (kind === "ALLOW" || kind === "APPROVED") return <Check size={15} />;
  if (kind === "BLOCK") return <ShieldX size={15} />;
  if (kind === "POLICY") return <Settings2 size={15} />;
  if (kind === "REJECTED") return <X size={15} />;
  return <Clock3 size={15} />;
}
function AuditList({ events, compact = false }: { events: AuditEvent[]; compact?: boolean }) {
  if (!events.length) return <Empty icon={History} title="No events yet" text="Evaluations and decisions appear here." />;
  return <div className={"audit-list" + (compact ? " compact" : "")}>{events.map((event) => <div className="audit-row" key={event.id}>
    <div className={"event-icon e-" + event.kind.toLowerCase()}><EventIcon kind={event.kind} /></div>
    <div className="event-copy"><div className="event-title">{event.title}<span className={"event-tag e-tag-" + event.kind.toLowerCase()}>{event.kind}</span></div><p>{event.detail}</p><div className="event-meta">{event.actor}<span>·</span>{dateLabel(event.at)}</div></div>
    {!compact && <code className="event-id">{event.id.slice(0, 15)}</code>}
  </div>)}</div>;
}
function ActionIcon({ type }: { type: ActionType }) {
  if (type === "read_resource" || type === "search") return <Search size={17} />;
  if (type === "write_resource") return <FileCheck2 size={17} />;
  if (type === "send_external") return <Globe2 size={17} />;
  if (type === "delete_resource" || type === "transfer_funds") return <AlertTriangle size={17} />;
  if (type === "change_permissions") return <LockKeyhole size={17} />;
  if (type === "execute_code") return <Terminal size={17} />;
  return <ExternalLink size={17} />;
}
function PolicyCard({ rule, toggle, remove }: { rule: PolicyRule; toggle: () => void; remove: () => void }) {
  const tone = rule.effect === "ALLOW" ? "green" : rule.effect === "BLOCK" ? "red" : "amber";
  return <article className={"policy-card" + (!rule.enabled ? " disabled" : "")}><div className="policy-card-head"><div className={"policy-symbol " + tone}>{rule.effect === "ALLOW" ? <Check size={17} /> : rule.effect === "BLOCK" ? <LockKeyhole size={17} /> : <Clock3 size={17} />}</div><span className={"decision-tag " + tone}>{rule.effect === "REQUIRE_APPROVAL" ? "REQUIRE APPROVAL" : rule.effect}</span></div>
    <h3>{rule.name}</h3><p>{rule.description}</p><div className="policy-scope"><span>ACTION</span><strong>{rule.actionTypes.map(labelFor).join(", ")}</strong><span>RESOURCE</span><code>{rule.resources.join(", ")}</code></div>
    <div className="policy-footer"><span className={rule.locked ? "locked" : "custom"}>{rule.locked ? <><LockKeyhole size={12} /> Locked baseline</> : <><Settings2 size={12} /> Custom restriction</>}</span>
      {rule.locked ? <span className="enforced"><i /> Enforced</span> : <div className="policy-actions"><button onClick={remove}>Remove</button><button className={"switch" + (rule.enabled ? " on" : "")} role="switch" aria-checked={rule.enabled} aria-label={(rule.enabled ? "Disable " : "Enable ") + rule.name} onClick={toggle}><span /></button></div>}
    </div>
  </article>;
}

export default function App() {
  const seed = useMemo(seedDemo, []);
  const [page, setPage] = useState<Page>("overview");
  const [mobileNav, setMobileNav] = useState(false);
  const [modal, setModal] = useState<"evaluate" | "rule" | null>(null);
  const [proposals, setProposals] = usePersisted<Proposal[]>(KEYS.proposals, seed.proposals);
  const [events, setEvents] = usePersisted<AuditEvent[]>(KEYS.audit, seed.events);
  const [customRules, setCustomRules] = usePersisted<PolicyRule[]>(KEYS.rules, []);
  const [filter, setFilter] = useState<"all" | RequestStatus>("all");
  const [query, setQuery] = useState("");
  const [notice, setNotice] = useState("");
  const [actionForm, setActionForm] = useState({ agent: "support-agent", actionType: "write_resource" as ActionType, resource: "workspace/launch-plan.md", summary: "Update the launch plan with revised messaging." });
  const [ruleForm, setRuleForm] = useState({ name: "Review outbound customer exports", description: "Customer exports need a human check before leaving the workspace.", effect: "REQUIRE_APPROVAL" as "BLOCK" | "REQUIRE_APPROVAL", actionType: "send_external" as ActionType, resourcePattern: "email/customer-export.csv" });
  const title = NAV.find((item) => item.id === page)?.label ?? "Overview";
  const rules = useMemo(() => [...DEFAULT_RULES, ...customRules], [customRules]);
  const pending = proposals.filter((p) => p.status === "pending").length;
  const blocked = proposals.filter((p) => p.status === "blocked").length;
  const allowed = proposals.filter((p) => p.status === "allowed" || p.status === "approved").length;
  const listed = useMemo(() => proposals.filter((p) => {
    const statusMatch = filter === "all" || p.status === filter;
    const needle = query.trim().toLowerCase();
    const queryMatch = !needle || [p.agent, p.resource, p.summary, p.id, p.matchedRule].some((v) => v.toLowerCase().includes(needle));
    return statusMatch && queryMatch;
  }).sort((a, b) => b.requestedAt.localeCompare(a.requestedAt)), [proposals, filter, query]);

  function log(kind: EventKind, titleText: string, detail: string, actor: string) {
    setEvents((current) => [{ id: id("evt"), at: new Date().toISOString(), actor, kind, title: titleText, detail }, ...current].slice(0, 500));
  }
  function evaluate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requestId = id("req");
    const requestedAt = new Date().toISOString();
    const result = evaluateAction({ id: requestId, agent: actionForm.agent, actionType: actionForm.actionType, resource: actionForm.resource, summary: actionForm.summary, requestedAt }, customRules);
    const status: RequestStatus = result.decision === "ALLOW" ? "allowed" : result.decision === "BLOCK" ? "blocked" : "pending";
    const proposal: Proposal = { id: requestId, agent: actionForm.agent.trim(), actionType: actionForm.actionType, resource: actionForm.resource.trim(), summary: actionForm.summary.trim(), requestedAt, decision: result.decision, status, reason: result.reason, matchedRule: result.matchedRules[0]?.name ?? "Fail-safe review" };
    setProposals((current) => [proposal, ...current]);
    log(result.decision === "ALLOW" ? "ALLOW" : result.decision === "BLOCK" ? "BLOCK" : "REVIEW", result.decision === "ALLOW" ? "Action allowed" : result.decision === "BLOCK" ? "Action blocked" : "Human review required", proposal.summary + " · " + proposal.resource, proposal.agent);
    setModal(null); setPage("requests"); setNotice("Evaluated by " + POLICY_VERSION + ". No external action was executed.");
  }
  function resolve(proposal: Proposal, outcome: "approve" | "reject") {
    try {
      const result = resolveApproval<{ id: string; status: "pending" | "approved" | "rejected"; reviewer?: string; reviewedAt?: string }>({ id: proposal.id, status: proposal.status as "pending" | "approved" | "rejected" }, outcome, "workspace.operator");
      setProposals((items) => items.map((p) => p.id === proposal.id ? { ...p, status: result.status as RequestStatus, reviewer: result.reviewer, reviewedAt: result.reviewedAt } : p));
      log(outcome === "approve" ? "APPROVED" : "REJECTED", outcome === "approve" ? "Request approved locally" : "Request rejected", proposal.summary + " · " + proposal.resource, "workspace.operator");
      setNotice(outcome === "approve" ? "Local approval recorded. Production integrations must enforce approval server-side." : "Request rejected and recorded locally.");
    } catch (err) { setNotice(err instanceof Error ? err.message : "Unable to resolve request."); }
  }
  function addRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const rule = createRestriction({ id: id("rule"), name: ruleForm.name, description: ruleForm.description, effect: ruleForm.effect, actionType: ruleForm.actionType, resourcePattern: ruleForm.resourcePattern });
      setCustomRules((current) => [rule, ...current]);
      log("POLICY", "Restriction added", rule.name + " · " + rule.resources.join(", "), "workspace.operator");
      setModal(null); setPage("policies"); setNotice("Restriction saved locally. Custom rules cannot grant new permissions.");
    } catch (err) { setNotice(err instanceof Error ? err.message : "Unable to create rule."); }
  }
  function toggleRule(rule: PolicyRule) {
    if (rule.locked) return;
    setCustomRules((items) => items.map((item) => item.id === rule.id ? { ...item, enabled: !item.enabled } : item));
    log("POLICY", rule.enabled ? "Restriction disabled" : "Restriction enabled", rule.name, "workspace.operator");
  }
  function removeRule(rule: PolicyRule) {
    if (rule.locked || !window.confirm("Remove this local restriction? Existing decisions remain in the audit log.")) return;
    setCustomRules((items) => items.filter((item) => item.id !== rule.id));
    log("POLICY", "Restriction removed", rule.name, "workspace.operator");
  }
  function exportAudit() {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), disclaimer: "Local browser export, not a trusted or tamper-proof server audit record.", policyVersion: POLICY_VERSION, events, proposals }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "backstop-audit-" + new Date().toISOString().slice(0, 10) + ".json"; anchor.click(); URL.revokeObjectURL(url);
    setNotice("Audit export generated from this browser's local data.");
  }
  async function copySnippet() {
    try { await navigator.clipboard.writeText(SNIPPET); setNotice("Integration example copied."); }
    catch { setNotice("Clipboard blocked. Select and copy the code manually."); }
  }
  function resetDemo() {
    if (!window.confirm("Reset local demo data and remove custom restrictions?")) return;
    const fresh = seedDemo(); setProposals(fresh.proposals); setEvents(fresh.events); setCustomRules([]); setFilter("all"); setQuery("");
    setNotice("Workspace reset to sample data.");
  }

  return <div className="app-shell">
    <aside className={"sidebar" + (mobileNav ? " open" : "")}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={23} /></div><div><div className="brand-name">BACKSTOP<span>.</span></div><div className="brand-sub">AGENT CONTROL PLANE</div></div><button className="icon-btn close-nav" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={16} /></button></div>
      <div className="workspace-switch"><div className="workspace-avatar">D</div><div className="workspace-text"><strong>Dev workspace</strong><span>Personal environment</span></div><ChevronDown size={15} /></div>
      <nav className="nav" aria-label="Main navigation">{["CONTROL", "GOVERNANCE", "BUILD"].map((group) => <div className="nav-group" key={group}><div className="nav-label">{group}</div>{NAV.filter((item) => item.group === group).map((item) => { const Icon = item.icon; return <button key={item.id} className={"nav-item" + (page === item.id ? " active" : "")} onClick={() => { setPage(item.id); setMobileNav(false); }}><Icon size={17} /><span>{item.label}</span>{item.id === "requests" && pending > 0 && <small>{pending}</small>}</button>; })}</div>)}</nav>
      <div className="sidebar-bottom"><div className="engine-card"><div className="engine-kicker"><i /> ENGINE STATUS</div><div className="engine-status">Operational <span>Local</span></div><p>Deterministic rules · No AI API</p></div><a className="source-link" href="https://github.com/kogleshofficial-hub/backstop" target="_blank" rel="noreferrer"><Github size={15} /> Source code <ExternalLink size={12} /></a><div className="sidebar-profile"><div className="profile-avatar">K</div><div className="workspace-text"><strong>Workspace operator</strong><span>Local reviewer</span></div><Settings2 size={15} /></div></div>
    </aside>
    {mobileNav && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <main className="main-shell">
      <header className="topbar"><div className="topbar-left"><button className="icon-btn mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button><div><div className="breadcrumb">BACKSTOP <span>/</span> {title.toUpperCase()}</div><h1>{title}</h1></div></div><div className="topbar-right"><div className="local-pill"><i /> LOCAL ONLY</div><button className="icon-btn topbar-code" onClick={() => setPage("developer")} aria-label="Developer center"><Code2 size={17} /></button><div className="top-avatar">K</div></div></header>
      {notice && <div className="notice" role="status"><Check size={15} /><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss notice"><X size={14} /></button></div>}
      <div className="page-content">
        {page === "overview" && <>
          <section className="hero"><div><div className="eyebrow"><i /> POLICY ENGINE <span>·</span> V1</div><h2>Every action.<br /><em>A deliberate decision.</em></h2><p>Put a deterministic policy check between an AI agent and the tools it wants to use.</p></div><button className="btn primary hero-button" onClick={() => setModal("evaluate")}><Plus size={17} /> Evaluate an action <ArrowRight size={15} /></button></section>
          <div className="environment-alert"><div className="alert-symbol"><ShieldAlert size={18} /></div><div><strong>Local sandbox is active</strong><p>This workspace evaluates examples only. It does not control external agents or execute real actions.</p></div><button onClick={() => setPage("developer")}>Integration notes <ArrowRight size={14} /></button></div>
          <section className="metrics"><Metric icon={Activity} label="Evaluated requests" value={proposals.length} caption="Current workspace" tone="neutral" /><Metric icon={Clock3} label="Awaiting review" value={pending} caption={pending ? "Human decision needed" : "Queue is clear"} tone="amber" /><Metric icon={ShieldX} label="Blocked by policy" value={blocked} caption="Baseline + restrictions" tone="red" /><Metric icon={ShieldCheck} label="Allowed / approved" value={allowed} caption="Recorded outcomes" tone="green" /></section>
          <div className="dashboard-grid">
            <section className="panel"><div className="panel-heading"><div><div className="kicker">POLICY OUTCOMES</div><h3>Decision overview</h3></div><span className="panel-meta"><i />Current workspace</span></div><div className="decision-summary"><div className="donut" style={{ "--allow": allowed, "--block": blocked, "--pending": pending, "--total": Math.max(1, proposals.length) } as React.CSSProperties}><div><strong>{proposals.length}</strong><span>requests</span></div></div><div className="legend">{[["green", "Allowed / approved", allowed], ["red", "Blocked", blocked], ["amber", "Needs review", pending]].map(([tone, caption, amount]) => <div className="legend-row" key={String(caption)}><i className={"swatch " + tone} /><span>{caption}</span><strong>{Number(amount)}</strong></div>)}</div></div><div className="panel-divider" /><div className="callout"><div><Fingerprint size={19} /></div><section><strong>Deterministic by design</strong><p>Same request + same enabled rules = same decision. No model guesswork and no usage credits.</p></section></div></section>
            <section className="panel"><div className="panel-heading"><div><div className="kicker">HUMAN-IN-THE-LOOP</div><h3>Approval queue</h3></div><button className="link-btn" onClick={() => { setPage("requests"); setFilter("pending"); }}>View queue <ArrowRight size={14} /></button></div>{pending === 0 ? <Empty icon={CheckCheck} title="All caught up" text="There are no requests waiting for review." /> : <div className="queue">{proposals.filter((p) => p.status === "pending").slice(0, 4).map((p) => <div className="queue-row" key={p.id}><div className="queue-icon"><Clock3 size={16} /></div><div className="queue-copy"><strong>{p.summary}</strong><span>{p.agent} · {ago(p.requestedAt)}</span></div><button className="icon-btn" aria-label={"Review " + p.id} onClick={() => { setPage("requests"); setFilter("pending"); }}><ArrowRight size={15} /></button></div>)}</div>}</section>
            <section className="panel"><div className="panel-heading"><div><div className="kicker">LATEST ACTIVITY</div><h3>Audit trail</h3></div><button className="link-btn" onClick={() => setPage("audit")}>All events <ArrowRight size={14} /></button></div><AuditList events={events.slice(0, 5)} compact /></section>
            <section className="panel"><div className="panel-heading"><div><div className="kicker">ACTIVE POLICY SET</div><h3>Baseline safeguards</h3></div><button className="icon-btn subtle" aria-label="View policies" onClick={() => setPage("policies")}><ArrowRight size={16} /></button></div><div className="preview-rule"><div className="preview-symbol red"><LockKeyhole size={15} /></div><div><strong>Destructive deletion</strong><span>Non-overridable baseline block</span></div><b className="decision-tag red">BLOCK</b></div><div className="preview-rule"><div className="preview-symbol amber"><Clock3 size={15} /></div><div><strong>Writes & external sends</strong><span>Pause for human review</span></div><b className="decision-tag amber">REVIEW</b></div><div className="preview-rule"><div className="preview-symbol green"><Check size={15} /></div><div><strong>Read-only actions</strong><span>Allowed by baseline</span></div><b className="decision-tag green">ALLOW</b></div><button className="full-link" onClick={() => setPage("policies")}>Inspect all {rules.length} rules <ArrowRight size={14} /></button></section>
          </div>
          <footer className="footer-note"><Shield size={14} /> Backstop v0.1.0 <span>·</span> {POLICY_VERSION}<div />Local data stays in this browser profile</footer>
        </>}

        {page === "requests" && <section className="page-section"><div className="page-intro"><div><div className="eyebrow"><i /> DECISION WORKFLOW</div><h2>Action requests</h2><p>Evaluate proposed work and resolve items that need a human decision.</p></div><button className="btn primary" onClick={() => setModal("evaluate")}><Plus size={16} /> New evaluation</button></div>
          <div className="toolbar"><div className="filter-tabs">{(["all", "pending", "allowed", "blocked", "approved", "rejected"] as const).map((value) => <button key={value} className={filter === value ? "selected" : ""} onClick={() => setFilter(value)}>{value === "all" ? "All requests" : statusLabel(value)}{value === "pending" && <small>{pending}</small>}</button>)}</div><label className="search-box"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search requests..." /></label></div>
          <div className="request-list">{listed.length === 0 ? <Empty icon={Search} title="No matching requests" text="Try another filter or submit a new action for evaluation." /> : listed.map((p) => <article className="request-card" key={p.id}><div className="request-top"><div className="request-action-icon"><ActionIcon type={p.actionType} /></div><div className="request-heading"><div className="request-title-row"><h3>{labelFor(p.actionType)}</h3><Badge status={p.status} /></div><p>{p.summary}</p></div><div className="request-time">{ago(p.requestedAt)}<code>{p.id.slice(0, 14)}</code></div></div><div className="request-meta"><div><span>REQUESTING AGENT</span><strong><i />{p.agent}</strong></div><div><span>TARGET RESOURCE</span><code>{p.resource}</code></div><div><span>MATCHED POLICY</span><strong>{p.matchedRule}</strong></div></div><div className={"rationale rationale-" + p.status}>{p.status === "blocked" ? <ShieldX size={15} /> : p.status === "pending" ? <Clock3 size={15} /> : <ShieldCheck size={15} />}<span>{p.reason}</span></div>{p.status === "pending" && <div className="request-actions"><span>Local record only — not a production authorization.</span><button className="btn quiet" onClick={() => resolve(p, "reject")}><X size={14} /> Reject</button><button className="btn primary" onClick={() => resolve(p, "approve")}><Check size={14} /> Approve locally</button></div>}{(p.status === "approved" || p.status === "rejected") && p.reviewedAt && <div className="resolution-note">Resolved by {p.reviewer} · {dateLabel(p.reviewedAt)}</div>}</article>)}</div>
        </section>}

        {page === "policies" && <section className="page-section"><div className="page-intro"><div><div className="eyebrow"><i /> GOVERNANCE</div><h2>Policy library</h2><p>Readable rules that decide whether a proposed action can continue.</p></div><button className="btn primary" onClick={() => setModal("rule")}><Plus size={16} /> Add restriction</button></div>
          <div className="policy-warning"><LockKeyhole size={18} /><div><strong>Baseline safety rules are locked</strong><p>Custom rules can BLOCK or REQUIRE APPROVAL. They cannot grant permissions or override hard-block safeguards.</p></div></div>
          <div className="policy-metrics"><div><span>POLICY VERSION</span><strong>{POLICY_VERSION}</strong></div><div><span>BASELINE RULES</span><strong>{DEFAULT_RULES.length}</strong></div><div><span>CUSTOM RESTRICTIONS</span><strong>{customRules.length}</strong></div><div><span>EVALUATION MODE</span><strong>Deterministic</strong></div></div>
          <div className="policy-grid">{rules.map((rule) => <PolicyCard key={rule.id} rule={rule} toggle={() => toggleRule(rule)} remove={() => removeRule(rule)} />)}</div>
          <div className="policy-footnote"><CircleHelp size={16} /><span>Custom policies restrict actions; they never grant permissions. This client-side policy workspace is not a trusted server enforcement boundary.</span></div>
        </section>}

        {page === "audit" && <section className="page-section"><div className="page-intro"><div><div className="eyebrow"><i /> TRACEABILITY</div><h2>Audit log</h2><p>A chronological record of evaluations, policy edits, and local reviewer outcomes.</p></div><div className="button-row"><button className="btn quiet" onClick={resetDemo}><Trash2 size={15} /> Reset demo</button><button className="btn primary" onClick={exportAudit}><Download size={15} /> Export JSON</button></div></div>
          <div className="audit-warning"><ShieldAlert size={16} /><span>This is an editable local browser record, not tamper-proof or server-owned compliance evidence.</span></div>
          <section className="panel audit-panel"><div className="panel-heading"><div><div className="kicker">EVENT STREAM</div><h3>{events.length} recorded events</h3></div><span className="panel-meta">Newest first</span></div><AuditList events={events} /></section>
        </section>}

        {page === "developer" && <section className="page-section"><div className="page-intro"><div><div className="eyebrow"><i /> BUILD WITH BACKSTOP</div><h2>Developer center</h2><p>The policy core is model-free. PostgreSQL-backed server components can enforce decisions before a registered tool runs.</p></div><a className="btn quiet" href="https://github.com/kogleshofficial-hub/backstop" target="_blank" rel="noreferrer"><Github size={16} /> Repository <ExternalLink size={13} /></a></div>
          <div className="developer-hero"><div className="dev-symbol"><Terminal size={23} /></div><div><div className="kicker">TYPESCRIPT CORE</div><h3>Check first. Execute second.</h3><p>Run a policy decision immediately before a tool call. Never execute first and check later.</p></div><span className="engine-pill"><i /> Local engine</span></div>
          <div className="developer-grid"><section className="panel code-panel"><div className="code-head"><div><div className="kicker">INTEGRATION PATTERN</div><strong>Gate a real server-side action</strong></div><button className="btn quiet btn-sm" onClick={copySnippet}><Copy size={14} /> Copy code</button></div><pre className="code-block"><code>{SNIPPET}</code></pre><div className="code-footnote"><LockKeyhole size={14} /> Integration pattern: implement trusted auth/ACL callbacks and server-registered tools. The local console does not execute this code.</div></section>
            <section className="panel"><div className="panel-heading"><div><div className="kicker">DECISION CONTRACT</div><h3>Possible outcomes</h3></div></div><div className="definition"><span className="decision-tag green">ALLOW</span><div><strong>Proceed to tool adapter</strong><p>Only after server-side identity and resource checks also pass.</p></div></div><div className="definition"><span className="decision-tag red">BLOCK</span><div><strong>Stop execution</strong><p>Locked baseline safeguards or matched restrictions deny the request.</p></div></div><div className="definition"><span className="decision-tag amber">REVIEW</span><div><strong>Pause for a reviewer</strong><p>Persist the request and wait for an authenticated decision.</p></div></div></section>
          </div>
          <section className="panel checklist"><div className="panel-heading"><div><div className="kicker">BEFORE PRODUCTION</div><h3>Required engineering work</h3></div></div>{[["Authenticate every agent", "Expiring, hashed, organization-scoped machine credentials are available; host routes must authenticate sessions and protect management APIs."], ["Enforce at the execution boundary", "The server-side gate wraps registered tools and checks policy, action scope, resource ACL, approval, audit and replay claim."], ["Persist approvals on the server", "The PostgreSQL adapter stores review requests and atomically consumes approval evidence; connect it to authenticated reviewer routes."], ["Add bypass and replay tests", "Unit regression tests cover malformed policies, approval binding, duplicates and storage failures; real adversarial integration tests remain required."]].map(([heading, detail], index) => <div className="checklist-row" key={heading}><code>0{index + 1}</code><div><strong>{heading}</strong><p>{detail}</p></div><span>{["Partial", "Implemented", "Storage added", "Tests pending"][index]}</span></div>)}</section>
        </section>}
      </div>
    </main>
    {modal && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setModal(null); }} role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header className="modal-head"><div className="modal-symbol">{modal === "evaluate" ? <ShieldCheck size={19} /> : <Settings2 size={19} />}</div><div><div className="kicker">{modal === "evaluate" ? "POLICY PLAYGROUND" : "LOCAL POLICY"}</div><h2 id="modal-title">{modal === "evaluate" ? "Evaluate an action" : "Create a restriction"}</h2></div><button className="icon-btn" aria-label="Close dialog" onClick={() => setModal(null)}><X size={17} /></button></header>
      {modal === "evaluate" ? <form className="modal-form" onSubmit={evaluate}><div className="form-note"><Shield size={15} /> The engine classifies this proposal. No real action will execute.</div><label>Requesting agent<input required minLength={2} maxLength={80} value={actionForm.agent} onChange={(e) => setActionForm({ ...actionForm, agent: e.target.value })} /></label><label>Action type<select value={actionForm.actionType} onChange={(e) => setActionForm({ ...actionForm, actionType: e.target.value as ActionType })}>{ACTION_CATALOG.map((a) => <option key={a.type} value={a.type}>{a.label}</option>)}</select></label><label>Target resource<input required maxLength={180} value={actionForm.resource} onChange={(e) => setActionForm({ ...actionForm, resource: e.target.value })} /></label><label>What is the agent asking to do?<textarea required minLength={5} maxLength={300} rows={3} value={actionForm.summary} onChange={(e) => setActionForm({ ...actionForm, summary: e.target.value })} /></label><div className="form-caption">{POLICY_VERSION} · No AI inference · No external API calls</div><div className="modal-actions"><button className="btn quiet" type="button" onClick={() => setModal(null)}>Cancel</button><button className="btn primary" type="submit"><ShieldCheck size={15} /> Run policy check</button></div></form> : <form className="modal-form" onSubmit={addRule}><div className="form-note"><LockKeyhole size={15} /> Custom rules can block or pause actions. They cannot grant permissions.</div><label>Rule name<input required minLength={3} maxLength={80} value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} /></label><label>Outcome<select value={ruleForm.effect} onChange={(e) => setRuleForm({ ...ruleForm, effect: e.target.value as "BLOCK" | "REQUIRE_APPROVAL" })}><option value="REQUIRE_APPROVAL">Require human approval</option><option value="BLOCK">Block action</option></select></label><label>Action type<select value={ruleForm.actionType} onChange={(e) => setRuleForm({ ...ruleForm, actionType: e.target.value as ActionType })}>{ACTION_CATALOG.map((a) => <option key={a.type} value={a.type}>{a.label}</option>)}</select></label><label>Resource pattern<input required maxLength={180} value={ruleForm.resourcePattern} onChange={(e) => setRuleForm({ ...ruleForm, resourcePattern: e.target.value })} /><small>Use * for any resource or a trailing /** for a subtree.</small></label><label>Reason<input required minLength={5} maxLength={220} value={ruleForm.description} onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })} /></label><div className="modal-actions"><button className="btn quiet" type="button" onClick={() => setModal(null)}>Cancel</button><button className="btn primary" type="submit"><Plus size={15} /> Save restriction</button></div></form>}
    </section></div>}
  </div>;
}
