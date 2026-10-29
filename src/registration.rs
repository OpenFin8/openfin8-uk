// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for OpenFin8:UK).
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.
//!
//! The shape follows the `openfin8-ca`/`openfin8-eu` registrations (the
//! per-jurisdiction identity): PG role `openfin8_uk_service` on the
//! `openfin8` vertical database, the UK scope vocabulary
//! `openfin8:uk:*`, the scope-mirror policy set seeded by `vertical
//! enroll`, and the staged-intent expiry schedule (24h - OBL).

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, AuditFinding, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, ScheduleDecl, ServiceActionEntry, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "openfin8:uk:read,openfin8:uk:write",
    role: "openfin8_uk_service",
    bypass_rls: false,
    database: "openfin8",
    cross_schema_grants: &[],
}];

/// M2M scope grants (CERTFREE-4V): the service's own workloads + the
/// proxy lanes (CERTFREE-8V, OBVERT) + the platform standard set.
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "openfin8:uk",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:flow:write",
        ],
    },
    M2mGrant {
        workload: "openfin8-uk",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:flow:write",
        ],
    },
    M2mGrant {
        workload: "openfin8-uk-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    M2mGrant {
        workload: "openfin8-uk-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "openfin8-uk-sys",
        scopes: &["sentin8:sys:tenants:read"],
    },
    M2mGrant {
        workload: "openfin8-uk-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
    // CERTFREE-8V: the uk→ledger proxy workload (the AIS reads).
    M2mGrant {
        workload: "openfin8-uk-ledger",
        scopes: &["bank8:ledger:accounts:read", "bank8:ledger:postings:read"],
    },
    // CERTFREE-8V: the uk→payments proxy workload (the domestic payments
    // + VRP initiations).
    M2mGrant {
        workload: "openfin8-uk-payments",
        scopes: &[
            "bank8:payments:payments:read",
            "bank8:payments:payments:write",
        ],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:consents:write",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:consents:read",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:recipient:read",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:recipient:write",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:provider:read",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:provider:write",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:policy:read",
    },
    AdminScope::Typed {
        role: "openfin8:uk:admin",
        scope: "openfin8:uk:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "UkObConsentInvalid",
        error_code: "uk_ob_consent_invalid",
        status_code: 400,
    },
    ErrorCode {
        enum_name: "UkObConsentRevoked",
        error_code: "uk_ob_consent_revoked",
        status_code: 400,
    },
    ErrorCode {
        enum_name: "UkObSignatureInvalid",
        error_code: "uk_ob_signature_invalid",
        status_code: 400,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "consents",
        label: "Consents",
        ui_endpoint: "/v1/admin/ui/consents",
        data_endpoint: "/v1/admin/consents",
        icon: "0xe69a",
    },
    AdminUiPage {
        route: "recipients",
        label: "Recipients",
        ui_endpoint: "/v1/admin/ui/recipients",
        data_endpoint: "/v1/admin/recipients",
        icon: "0xe2c8",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
];

/// The scope-mirror policy set (the CA/EU shape): action-granular scope
/// permits over the LIVE effective scope set.
const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"openfin8:uk:consents:read\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:read\", resource) when { principal.scopes.contains(\"openfin8:uk:consents:read\") };\npermit(principal, action == Action::\"openfin8:uk:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:write\", resource) when { principal.scopes.contains(\"openfin8:uk:consents:write\") };\npermit(principal, action == Action::\"openfin8:uk:consents:write\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"openfin8:uk:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:read\", resource) when { principal.scopes.contains(\"openfin8:uk:recipient:read\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:read\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:write\", resource) when { principal.scopes.contains(\"openfin8:uk:recipient:write\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:write\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:recipient:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:provider:read\", resource) when { principal.scopes.contains(\"openfin8:uk:provider:read\") };\npermit(principal, action == Action::\"openfin8:uk:provider:read\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:provider:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:provider:write\", resource) when { principal.scopes.contains(\"openfin8:uk:provider:write\") };\npermit(principal, action == Action::\"openfin8:uk:provider:write\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:provider:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:policy:read\", resource) when { principal.scopes.contains(\"openfin8:uk:policy:read\") };\npermit(principal, action == Action::\"openfin8:uk:policy:read\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:policy:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:uk:policy:write\", resource) when { principal.scopes.contains(\"openfin8:uk:policy:write\") };\npermit(principal, action == Action::\"openfin8:uk:policy:write\", resource) when { principal.scopes.contains(\"openfin8:uk:admin\") };\npermit(principal, action == Action::\"openfin8:uk:policy:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n";

const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for openfin8:uk over the LIVE effective scope set (design §3.1d). Step 5 is the only gate.",
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

const AUDIT_FINDINGS: &[AuditFinding] = &[
    AuditFinding {
        finding: "Integration credentials stored without a secret reference",
        recommendation: "The ASPSP signing key (OPENFIN8_UK_SIGNING_KEY_REF - PS256) and any third-party credential must be stored as a sentin8-secrets:// reference. The sentin8-secrets crate resolves the reference to the actual value at runtime.",
    },
];

const SERVICE_ACTIONS: &[ServiceActionEntry] = &[ServiceActionEntry {
    action: "uk_consent_start",
    service_type: "openfin8:uk",
    platform_domain_key: "openfin8:uk",
    method: "POST",
    endpoint: "/v1/recipient/consents/start",
    scope: "openfin8:uk:recipient:write",
}];

/// The staged-intent expiry sweep (OBL: un-authorized intents die at
/// 24h - the declarative schedule). The sweep proxy-calls
/// the adapter's internal expiry endpoint on fire.
const SCHEDULES: &[ScheduleDecl] = &[ScheduleDecl {
    schedule_type: "uk-staged-intent-expiry",
    cron_expression: "0 3 * * *",
    timezone: "UTC",
    target_config: "{\"internalPath\": \"/v1/internal/sweep/staged-intents\"}",
    max_retries: 3,
}];

fn consent_providers_json() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "feature": "openfin8-uk",
        "data_type": "accounts",
        "service_type": "openfin8:uk",
        "platform_domain_key": "openfin8:uk",
        "endpoint": "/v1/auth/consent/accounts",
        "scope": "openfin8:uk:consents:read",
        "response_key": "accounts"
    })]
}

fn consent_flows_json() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "id": "uk_ob_intent_authorization",
        "trigger_patterns": ["openfin8:uk:recipient:*"],
        "service_type": "openfin8:uk",
        "ui_endpoint": "/v1/auth/consent/ui",
        "approve_endpoint": "/v1/auth/consent/approve",
        "deny_endpoint": "/v1/auth/consent/deny"
    })]
}

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::UkOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let consent_providers: &'static [serde_json::Value] =
        Box::leak(consent_providers_json().into_boxed_slice());
    let consent_flows: &'static [serde_json::Value] =
        Box::leak(consent_flows_json().into_boxed_slice());
    let reg = Registration {
        service_type: "openfin8:uk",
        subdomain: "openfin8-uk",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers,
        consent_flows,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: SCHEDULES,
        admin_ui: Some(AdminUi {
            label: "OpenUK",
            icon: "0xe69a",
            service_flag: "openfin8-uk",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        audit_findings: Some(AUDIT_FINDINGS),
        service_actions: Some(SERVICE_ACTIONS),
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
