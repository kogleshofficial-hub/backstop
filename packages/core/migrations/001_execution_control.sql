-- BACKSTOP production-adapter schema starter (PostgreSQL 15+ recommended).
-- Apply with a migration/owner role. The application role should not own these tables.
-- Keep all queries scoped by organization_id, even when row-level policies also apply.

CREATE TABLE IF NOT EXISTS backstop_agent_credentials (
  credential_id text PRIMARY KEY,
  organization_id text NOT NULL,
  agent_id text NOT NULL,
  key_prefix text NOT NULL UNIQUE,
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}
  organization_id text PRIMARY KEY,
  policy_version text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(btrim(organization_id)) > 0),
  CHECK (length(btrim(policy_version)) > 0)
);

CREATE TABLE IF NOT EXISTS backstop_policy_rules (
  organization_id text NOT NULL,
  policy_version text NOT NULL,
  rule_id text NOT NULL,
  name text NOT NULL,
  description text NOT NULL,
  effect text NOT NULL CHECK (effect IN ('BLOCK', 'REQUIRE_APPROVAL')),
  action_types text[] NOT NULL CHECK (cardinality(action_types) > 0),
  resource_patterns text[] NOT NULL CHECK (cardinality(resource_patterns) > 0),
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 300,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, policy_version, rule_id),
  FOREIGN KEY (organization_id) REFERENCES backstop_policy_sets (organization_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS backstop_approval_requests (
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  action_type text NOT NULL,
  resource text NOT NULL,
  summary text NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  policy_version text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected', 'consumed', 'expired')),
  reviewer_id text,
  approval_id text UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz,
  PRIMARY KEY (organization_id, request_id),
  CHECK (length(btrim(request_id)) > 0),
  CHECK (length(btrim(agent_id)) > 0),
  CHECK (length(btrim(resource)) > 0)
);

CREATE INDEX IF NOT EXISTS backstop_approval_requests_review_queue
  ON backstop_approval_requests (organization_id, created_at)
  WHERE status = 'pending';

-- Use INSERT ... ON CONFLICT DO NOTHING as an atomic claim. A conflict must return false;
-- never update an old digest to make a duplicate request appear new.
CREATE TABLE IF NOT EXISTS backstop_execution_claims (
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  action_type text NOT NULL,
  resource text NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  claimed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, request_id)
);

CREATE INDEX IF NOT EXISTS backstop_execution_claims_agent_time
  ON backstop_execution_claims (organization_id, agent_id, claimed_at DESC);

CREATE TABLE IF NOT EXISTS backstop_audit_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN (
    'BLOCKED', 'APPROVAL_REQUIRED', 'APPROVAL_APPROVED', 'APPROVAL_REJECTED',
    'CREDENTIAL_CREATED', 'CREDENTIAL_REVOKED', 'POLICY_PUBLISHED', 'EXECUTION_AUTHORIZED',
    'EXECUTION_SUCCEEDED', 'EXECUTION_FAILED', 'GATE_ERROR'
  )),
  decision text CHECK (decision IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL') OR decision IS NULL),
  policy_version text NOT NULL,
  action_type text,
  resource text,
  input_digest char(64) CHECK (input_digest IS NULL OR input_digest ~ '^[a-f0-9]{64}$'),
  reason text NOT NULL,
  inserted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS backstop_audit_events_org_time
  ON backstop_audit_events (organization_id, inserted_at DESC);

CREATE INDEX IF NOT EXISTS backstop_audit_events_request
  ON backstop_audit_events (organization_id, request_id, inserted_at);

-- Security deployment requirement:
-- Grant the runtime role only the exact SELECT/INSERT/UPDATE privileges its adapters need.
-- In particular, do NOT grant UPDATE, DELETE, or TRUNCATE on backstop_audit_events to the
-- runtime role. Keep schema ownership on a separate migration role.
-- This schema alone does not authenticate users, configure RLS, or prove adapter correctness.
),
  allowed_actions text[] NOT NULL CHECK (cardinality(allowed_actions) > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (length(btrim(organization_id)) > 0),
  CHECK (length(btrim(agent_id)) > 0),
  CHECK (length(btrim(key_prefix)) > 0),
  CHECK (length(btrim(created_by)) > 0),
  CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS backstop_agent_credentials_org_time
  ON backstop_agent_credentials (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS backstop_agent_credentials_active_org
  ON backstop_agent_credentials (organization_id, agent_id, expires_at)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS backstop_policy_sets (
  organization_id text PRIMARY KEY,
  policy_version text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(btrim(organization_id)) > 0),
  CHECK (length(btrim(policy_version)) > 0)
);

CREATE TABLE IF NOT EXISTS backstop_policy_rules (
  organization_id text NOT NULL,
  policy_version text NOT NULL,
  rule_id text NOT NULL,
  name text NOT NULL,
  description text NOT NULL,
  effect text NOT NULL CHECK (effect IN ('BLOCK', 'REQUIRE_APPROVAL')),
  action_types text[] NOT NULL CHECK (cardinality(action_types) > 0),
  resource_patterns text[] NOT NULL CHECK (cardinality(resource_patterns) > 0),
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 300,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, policy_version, rule_id),
  FOREIGN KEY (organization_id) REFERENCES backstop_policy_sets (organization_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS backstop_approval_requests (
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  action_type text NOT NULL,
  resource text NOT NULL,
  summary text NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  policy_version text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected', 'consumed', 'expired')),
  reviewer_id text,
  approval_id text UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz,
  PRIMARY KEY (organization_id, request_id),
  CHECK (length(btrim(request_id)) > 0),
  CHECK (length(btrim(agent_id)) > 0),
  CHECK (length(btrim(resource)) > 0)
);

CREATE INDEX IF NOT EXISTS backstop_approval_requests_review_queue
  ON backstop_approval_requests (organization_id, created_at)
  WHERE status = 'pending';

-- Use INSERT ... ON CONFLICT DO NOTHING as an atomic claim. A conflict must return false;
-- never update an old digest to make a duplicate request appear new.
CREATE TABLE IF NOT EXISTS backstop_execution_claims (
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  action_type text NOT NULL,
  resource text NOT NULL,
  input_digest char(64) NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  claimed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, request_id)
);

CREATE INDEX IF NOT EXISTS backstop_execution_claims_agent_time
  ON backstop_execution_claims (organization_id, agent_id, claimed_at DESC);

CREATE TABLE IF NOT EXISTS backstop_audit_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL,
  organization_id text NOT NULL,
  request_id text NOT NULL,
  agent_id text NOT NULL,
  tool_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN (
    'BLOCKED', 'APPROVAL_REQUIRED', 'APPROVAL_APPROVED', 'APPROVAL_REJECTED',
    'CREDENTIAL_CREATED', 'CREDENTIAL_REVOKED', 'EXECUTION_AUTHORIZED',
    'EXECUTION_SUCCEEDED', 'EXECUTION_FAILED', 'GATE_ERROR'
  )),
  decision text CHECK (decision IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL') OR decision IS NULL),
  policy_version text NOT NULL,
  action_type text,
  resource text,
  input_digest char(64) CHECK (input_digest IS NULL OR input_digest ~ '^[a-f0-9]{64}$'),
  reason text NOT NULL,
  inserted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS backstop_audit_events_org_time
  ON backstop_audit_events (organization_id, inserted_at DESC);

CREATE INDEX IF NOT EXISTS backstop_audit_events_request
  ON backstop_audit_events (organization_id, request_id, inserted_at);

-- Security deployment requirement:
-- Grant the runtime role only the exact SELECT/INSERT/UPDATE privileges its adapters need.
-- In particular, do NOT grant UPDATE, DELETE, or TRUNCATE on backstop_audit_events to the
-- runtime role. Keep schema ownership on a separate migration role.
-- This schema alone does not authenticate users, configure RLS, or prove adapter correctness.
