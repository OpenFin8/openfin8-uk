-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
-- SPDX-License-Identifier: Apache-2.0

-- OpenFin8:UK - the service's own schema `openfin8_uk` (schema-per-service):
-- openfin8_uk_* domain tables + openfin8_uk.outbox / openfin8_uk.audit_journal
-- producer tables, all FORCE-RLS env-scoped (provider_profiles is the public
-- cross-env catalog - no RLS by design, the CA/EU v2 convergence).
--
-- THE INTENT-BASED CONSENT MODEL (openfin8-uk DESIGN.md §3): unlike the
-- FDX single-grant shape, OBL stages an INTENT - the TPP creates the
-- consent resource with a client_credentials token (TPP identification
-- only, never a PSU token), the PSU authorizes the intent at the ASPSP
-- (the FAPI hybrid flow with the intent bound into the request object),
-- and the issued access token is BOUND TO THE INTENT: data calls resolve
-- consent by intent id (the same no-consent-no-data chokepoint, with the
-- intent as the join key).
--
-- The OB four-state consent model renders over the kernel's states:
--   AwaitingAuthorisation <- staged (kernel awaiting_authorization)
--   Authorised            <- the PSU authorized the intent (kernel active)
--   Rejected              <- the PSU denied (kernel revoked, deny path)
--   Consumed              <- a one-time consent consumed (kernel consumed)
-- with the terminal Revoked for the TPP-DELETE/PSU revocation paths -
-- subsequent reads answer 400 for the dead consent (the OBL wire
-- behavior mapped from the kernel's terminal-revocation invariant).

CREATE SCHEMA IF NOT EXISTS openfin8_uk;

-- ── The PROVIDER grant ledger: the intent-staged OB consent ─────────
CREATE TABLE IF NOT EXISTS openfin8_uk.consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    customer_id     UUID,
    recipient_id    TEXT,
    provider_id     TEXT,
    provider_name   TEXT,
    -- The OB four-state + Revoked rendering over the kernel states:
    -- awaiting_authorization | authorised | rejected | consumed | revoked
    status          TEXT NOT NULL DEFAULT 'awaiting_authorization'
                    CHECK (status IN ('awaiting_authorization', 'authorised',
                                      'rejected', 'consumed', 'revoked')),
    -- The OB role the consent serves: aisp | pisp | cbpii.
    role            TEXT NOT NULL CHECK (role IN ('aisp', 'pisp', 'cbpii')),
    -- The OB consent resource family: account-access | domestic-payment |
    -- domestic-vrp | funds-confirmation (the staged resource's own kind).
    resource        TEXT NOT NULL,
    -- The OB Permissions the consent requests (ReadAccountsBasic etc. -
    -- a CSDF vocabulary over the same filter engine).
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    -- THE INTENT: the staged consent resource serialized verbatim (the
    -- OB body the TPP POSTed) - the authorization journey + the data
    -- calls resolve everything from it (core's intent_payload column).
    intent_payload  JSONB NOT NULL DEFAULT '{}',
    -- The expiration the consent body requested (OBL
    -- ExpirationDateTime; absent = the default window).
    expires_at      TIMESTAMPTZ,
    -- The staged-intent expiry (OBL: un-authorized intents die at 24h -
    -- the sweep's window; distinct from the granted consent's own expiry).
    staged_expires_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_consents_env ON openfin8_uk.consents (env_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_uk_consents_customer ON openfin8_uk.consents (customer_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_uk_consents_status ON openfin8_uk.consents (status);
CREATE INDEX IF NOT EXISTS idx_openfin8_uk_consents_staged_expiry
    ON openfin8_uk.consents (staged_expires_at)
    WHERE status = 'awaiting_authorization';

-- ── The VRP control parameters (UK invariant 4) ──────────────────────
-- The domestic-vrp consent's ControlParameters (max-amount, periodic
-- limits) - carried on the consent and ENFORCED at initiation time.
CREATE TABLE IF NOT EXISTS openfin8_uk.vrp_control_parameters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    consent_id      UUID NOT NULL REFERENCES openfin8_uk.consents(id) ON DELETE CASCADE,
    -- The maximum single-payment amount (OB MaxSinglesAmount).
    max_single_amount NUMERIC,
    -- The maximum cumulative amount per period (OB MaximumSinglesAmount/
    -- PeriodicLimits).
    max_periodic_amount NUMERIC,
    -- The period unit (day | week | fortnight | month | half-year | year |
    -- hour - the OB PeriodicLimits vocabulary).
    period_unit     TEXT,
    -- The number of periods the limit covers.
    period_count    INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_vrp_params_consent
    ON openfin8_uk.vrp_control_parameters (consent_id);

-- ── The RECIPIENT registry (the recipient tenant's own bookkeeping) ──
-- The two-ledger model (unchanged): the recipient keeps its own per-ASPSP
-- client registry; the DCR carries the OB Directory software-statement
-- assertion (SSA).
CREATE TABLE IF NOT EXISTS openfin8_uk.recipients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    name            TEXT NOT NULL,
    -- The DCR-registered OAuth client id at the provider's AS (per
    -- (recipient env, provider)).
    client_id       TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    -- The OB Directory software-statement id (the SSA's
    -- software_statement_id claim) - the TPP's Directory identity.
    software_statement_id TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, client_id, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_recipients_env ON openfin8_uk.recipients (env_id);

CREATE TABLE IF NOT EXISTS openfin8_uk.recipient_consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    customer_id     UUID NOT NULL,
    provider_id     TEXT NOT NULL,
    provider_name   TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'awaiting_authorization', 'authorised',
                                      'rejected', 'consumed', 'revoked')),
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    selected_account_ids TEXT[] NOT NULL DEFAULT '{}',
    token_ref       TEXT,
    refresh_ref     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_rcpt_consents_env ON openfin8_uk.recipient_consents (env_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_uk_rcpt_consents_customer ON openfin8_uk.recipient_consents (customer_id);

-- ── The provider catalog (the public cross-env registry - NO RLS by
-- design; the CA/EU v2 convergence).
CREATE TABLE IF NOT EXISTS openfin8_uk.provider_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    provider_name   TEXT NOT NULL,
    issuer_url      TEXT NOT NULL,
    -- The OBL R/W API version this ASPSP serves (default 3.1.11).
    ob_version      TEXT NOT NULL DEFAULT '3.1.11',
    -- The roles this ASPSP serves (aisp/pisp/cbpii).
    roles           TEXT[] NOT NULL DEFAULT '{aisp,pisp,cbpii}',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, provider_name)
);

-- ── The producer tables (the platform contract: outbox + audit) ──────
CREATE TABLE IF NOT EXISTS openfin8_uk.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    idempotency_key TEXT,
    stream_family   TEXT NOT NULL DEFAULT 'openfin8-uk',
    publisher_service TEXT NOT NULL DEFAULT 'openfin8:uk',
    relayed         BOOLEAN NOT NULL DEFAULT FALSE,
    relay_attempts  INTEGER NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_outbox_unrelayed
    ON openfin8_uk.outbox (relayed, next_retry_at)
    WHERE NOT relayed;

CREATE TABLE IF NOT EXISTS openfin8_uk.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL DEFAULT 'unknown',
    target_resource_type  TEXT,
    target_resource_id    TEXT,
    actor_user_id         TEXT,
    actor_subject_type    TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT FALSE,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_uk_audit_unpushed
    ON openfin8_uk.audit_journal (pushed)
    WHERE NOT pushed;

-- ── RLS: FORCE on every tenant-scoped table; env_id-pinned policies ──
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'consents', 'vrp_control_parameters', 'recipients', 'recipient_consents'
    ]
    LOOP
        EXECUTE format('ALTER TABLE openfin8_uk.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE openfin8_uk.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON openfin8_uk.%I', t || '_dml', t);
        EXECUTE format(
            'CREATE POLICY %I ON openfin8_uk.%I FOR ALL
             USING (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())
             WITH CHECK (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())',
            t || '_dml', t);
    END LOOP;
END $$;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['outbox', 'audit_journal']
    LOOP
        EXECUTE format('ALTER TABLE openfin8_uk.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE openfin8_uk.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON openfin8_uk.%I', t || '_dml', t);
        EXECUTE format(
            'CREATE POLICY %I ON openfin8_uk.%I FOR ALL
             USING (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())
             WITH CHECK (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())',
            t || '_dml', t);
    END LOOP;
END $$;

-- provider_profiles: the public cross-env catalog - NO RLS.
ALTER TABLE openfin8_uk.provider_profiles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE openfin8_uk.provider_profiles DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_profiles_select ON openfin8_uk.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_insert ON openfin8_uk.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_update ON openfin8_uk.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_delete ON openfin8_uk.provider_profiles;

-- Per-service role grants + search_path (F1 - §4.3e):
-- The service connects via its own PostgreSQL role (openfin8_uk_service,
-- created by `sentin8-cli vertical enroll` from this service's
-- --print-registration --section=pg_roles). RLS only ENFORCES when the
-- service does NOT bypass it. These grants give the role table access; the
-- RLS policies scope the rows.
-- The search_path puts the service's OWN schema FIRST (outbox/audit_journal
-- resolution for the shell's relay + journal pusher; unqualified
-- openfin8_uk_* domain tables resolve here too), then public (RLS helpers).
-- The `vertical enroll` never-clobber block preserves this role-level
-- setting.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openfin8_uk_service') THEN
        ALTER ROLE openfin8_uk_service SET search_path = openfin8_uk, public;
        GRANT USAGE ON SCHEMA openfin8_uk TO openfin8_uk_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA openfin8_uk
            TO openfin8_uk_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA openfin8_uk
            TO openfin8_uk_service;
    END IF;
END $$;