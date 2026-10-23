# BACKSTOP

**A deterministic policy gate and approval workflow for AI agent actions.**

BACKSTOP is infrastructure for developers who want agent actions checked before real tools run. It provides a TypeScript policy engine, an embeddable server-side execution gate, PostgreSQL storage/approval adapters, and a local console for inspecting policy decisions.

## What is implemented

- Deterministic `ALLOW`, `BLOCK`, and `REQUIRE_APPROVAL` policy evaluation.
- Locked baseline blocks for destructive deletion and money transfers.
- Fail-closed checks for malformed requests and invalid custom policy configuration.
- Policy scenario runner for regression tests.
- Server-side gate with fixed server-registered tool/action mapping, authenticated principal contract, app-level resource authorization, canonical input snapshot and SHA-256 digest.
- Durable approval request records and atomic approval consumption contract.
- PostgreSQL adapter for versioned organization policies, pending approval queue, reviewer decisions, one-time execution claims, and audit event inserts.
- Starter PostgreSQL schema at `packages/core/migrations/001_execution_control.sql`.
- Unit tests and GitHub Actions CI, including high/critical dependency audit checks.
- No AI API or paid model credits required for these features.

## Run the local console

Requirements: Node.js 22.12+ and npm.

```sh
npm install
npm run dev
```

Open the local URL printed by Vite.

Validate the current checkout:

```sh
npm test
npm run check
npm run build
npm audit --audit-level=high
```

## Use the execution gate

The gate and adapter are package entry points:

- `@backstop/core/execution-gate`
- `@backstop/core/postgres-adapter`
- `@backstop/core/scenarios`

The PostgreSQL adapter accepts a compatible `pg.Pool`. Install the host app's database client with `npm install pg` and `npm install -D @types/pg`, configure `DATABASE_URL` as a server-side secret, then apply the schema with:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f packages/core/migrations/001_execution_control.sql
```

See [the execution-gate setup guide](docs/execution-gate.md), [the storage adapter contract](docs/storage-adapter-contract.md), and [policy testing](docs/policy-testing.md). Never expose database credentials in browser code or commit them to the repository.

## Important production boundary

The local dashboard still stores its own examples/rules/approvals in the browser; it is not a production security boundary. The server-side gate and PostgreSQL adapter are reusable security components, **not a complete hosted SaaS**. They require the host application's real session/authentication layer, organization membership checks, reviewer authorization, object-level ACL, restricted database credentials, a deployment, and real integration tests.

The database migration is a starter schema: it must be reviewed and applied to an actual PostgreSQL database. The adapter's callbacks must be connected to trusted application identity and ACL services. A policy decision does not prove the agent's resource identifier is honest; the registered tool's executor must perform the same operation against the same verified resource.

Before protecting production systems, add and verify rate limiting, abuse monitoring, secret management/rotation, backup/recovery, idempotent side-effect semantics, audit retention/access controls, multi-tenant isolation tests, bypass/replay tests, observability, and an independent security review. The execution claim intentionally refuses automatic replay after uncertain outcomes; recovery needs a controlled operator workflow.

## Product direction

The long-term product goal is an enforcement and governance layer that teams can embed between any AI agent and the real tools it can invoke. Generic policy controls already exist in the market, so a viable business needs a sharper proven advantage, reliable integrations, measurable prevention of unsafe actions, and developer/customer adoption. No claim of complete agent security, certification, customer traction, or billion-dollar valuation is made.

BACKSTOP is early-stage software under active development.
