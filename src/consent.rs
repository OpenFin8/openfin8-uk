// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The intent-based consent model (DESIGN.md §3).
//!
//! Unlike the FDX single-grant shape, OBL stages an **intent**: the TPP
//! creates the consent resource with a `client_credentials` token (TPP
//! identification only - never a PSU token; UK invariant 2), the PSU
//! authorizes the intent at the ASPSP (the FAPI hybrid flow with the
//! intent bound into the request object), and the issued access token is
//! **bound to the intent**: data calls resolve consent by intent id -
//! the same no-consent-no-data chokepoint, with intent as the join key.
//!
//! The OB four-state model renders over the kernel's states:
//! `AwaitingAuthorisation` (kernel `awaiting_authorization`) →
//! `Authorised` (kernel `active`) → `Rejected` (the deny path) /
//! `Consumed` (a one-time consent consumed), with terminal `Revoked` -
//! subsequent reads answer `400` for the dead consent (the OBL wire
//! behavior mapped from the kernel's terminal-revocation invariant).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use utoipa::ToSchema;
use uuid::Uuid;

use openfin8_core::profile::Profile;
use sentin8::auth::client::AuthContext;
use sentin8::shield::{EvalTarget, PolicyEngine};

// ── The state machines (pure, unit-tested) ─────────────────────────────

/// The OB consent states (the four-state + the terminal Revoked rendering
/// over the kernel states).
pub const OB_AWAITING: &str = "awaiting_authorization";
pub const OB_AUTHORISED: &str = "authorised";
pub const OB_REJECTED: &str = "rejected";
pub const OB_CONSUMED: &str = "consumed";
pub const OB_REVOKED: &str = "revoked";

/// The OB roles the consent serves.
pub const ROLE_AISP: &str = "aisp";
pub const ROLE_PISP: &str = "pisp";
pub const ROLE_CBPII: &str = "cbpii";

/// The OB consent-resource families.
pub const RESOURCE_ACCOUNT_ACCESS: &str = "account-access";
pub const RESOURCE_DOMESTIC_PAYMENT: &str = "domestic-payment";
pub const RESOURCE_DOMESTIC_VRP: &str = "domestic-vrp";
pub const RESOURCE_FUNDS_CONFIRMATION: &str = "funds-confirmation";

/// The pure state-transition table for the OB consent machine.
/// `revoke` is terminal from every non-revoked state; `consume` only
/// from `Authorised` (a one-time consent consumed); the authorization
/// observation moves `AwaitingAuthorisation → Authorised` (never a
/// direct assertion - the PSU journey drives it).
pub fn consent_transition(from: &str, event: &str) -> Option<String> {
    match (from, event) {
        (_, "revoke") if from != OB_REVOKED => Some(OB_REVOKED.to_string()),
        (OB_AWAITING, "psu_denied") => Some(OB_REJECTED.to_string()),
        (OB_AWAITING, "psu_authorised") => Some(OB_AUTHORISED.to_string()),
        (OB_AWAITING, "staged_expired") => Some(OB_REJECTED.to_string()),
        (OB_AUTHORISED, "consumed") => Some(OB_CONSUMED.to_string()),
        (OB_AUTHORISED, "psu_authorised") => Some(OB_AUTHORISED.to_string()),
        (OB_AUTHORISED, "expired") => Some(OB_REJECTED.to_string()),
        // Terminal states never leave.
        _ => None,
    }
}

/// The OBL wire verdict for a consent state at a data call: the OBL
/// error semantics (UK DESIGN §5) - unknown resource id → 400; the
/// revoked/dead consent's reads → 400 (never a bare 404: the resource
/// IS known, it is dead); `AwaitingAuthorisation` → 400 (the intent is
/// not yet authorized); only `Authorised` serves.
pub fn read_verdict(status: &str) -> Result<(), (u16, &'static str)> {
    match status {
        OB_AUTHORISED => Ok(()),
        OB_AWAITING => Err((
            400,
            "the consent is awaiting authorization - the intent has not been authorized yet",
        )),
        OB_REJECTED => Err((400, "the consent was rejected")),
        OB_CONSUMED => Err((
            400,
            "the consent was consumed - one-time consents do not repeat",
        )),
        OB_REVOKED => Err((
            400,
            "the consent was revoked - subsequent reads answer 400 (the dead consent)",
        )),
        _ => Err((400, "unknown consent state")),
    }
}

/// Validate the role + resource pairing (the OBL role-segmented paths:
/// the consent's role must match the surface that serves it).
pub fn validate_role_resource(role: &str, resource: &str) -> Result<(), String> {
    let ok = matches!(
        (role, resource),
        (ROLE_AISP, RESOURCE_ACCOUNT_ACCESS)
            | (ROLE_PISP, RESOURCE_DOMESTIC_PAYMENT)
            | (ROLE_PISP, RESOURCE_DOMESTIC_VRP)
            | (ROLE_CBPII, RESOURCE_FUNDS_CONFIRMATION)
    );
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the {role} role does not stage {resource} consents"
        ))
    }
}

/// Validate the OB Permissions vocabulary (the CSDF input; the known
/// OB permission set - unknown permissions reject, never grant).
pub const OB_PERMISSIONS: &[&str] = &[
    "ReadAccountsBasic",
    "ReadAccountsDetail",
    "ReadBalances",
    "ReadBeneficiariesBasic",
    "ReadBeneficiariesDetail",
    "ReadDirectDebits",
    "ReadProducts",
    "ReadStandingOrdersBasic",
    "ReadStandingOrdersDetail",
    "ReadTransactionsBasic",
    "ReadTransactionsCredits",
    "ReadTransactionsDebits",
    "ReadTransactionsDetail",
    "ReadOffers",
    "ReadPAN",
    "ReadParty",
    "ReadPartyPSU",
    "ReadScheduledPaymentsBasic",
    "ReadScheduledPaymentsDetail",
    "ReadStatementsBasic",
    "ReadStatementsDetail",
];

pub fn validate_permissions(permissions: &[String]) -> Result<(), String> {
    if permissions.is_empty() {
        return Err("the consent requests at least one OB Permission".into());
    }
    for p in permissions {
        if !OB_PERMISSIONS.contains(&p.as_str()) {
            return Err(format!("unknown OB Permission '{p}'"));
        }
    }
    Ok(())
}

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// `POST .../account-access-consents` request body (the OB
/// `OBReadConsentResponse1`-shaped staging body): the intent the TPP
/// stages.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StageConsentRequest {
    /// The OB Permissions requested.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// The ExpirationDateTime of the consent (ISO 8601; absent = the
    /// default window).
    #[serde(rename = "ExpirationDateTime", default)]
    pub expiration_date_time: Option<String>,
    /// The TransactionFromDateTime (AIS: the lookback window start).
    #[serde(rename = "TransactionFromDateTime", default)]
    pub transaction_from_date_time: Option<String>,
    /// The TransactionToDateTime (AIS).
    #[serde(rename = "TransactionToDateTime", default)]
    pub transaction_to_date_time: Option<String>,
    /// The risk payload (genuinely freeform - the OB risk document).
    #[serde(default)]
    pub risk: serde_json::Value,
}

/// The OB consent document (the wire shape - the `Data` of the
/// `OBReadConsentResponse1`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentResponse {
    /// The OB ConsentId (IS the core consent id).
    #[serde(rename = "ConsentId")]
    pub consent_id: Uuid,
    /// The creation timestamp.
    #[serde(rename = "CreationDateTime")]
    pub creation_date_time: chrono::DateTime<chrono::Utc>,
    /// The OB consent status.
    pub status: String,
    /// The OB status-update timestamp.
    #[serde(rename = "StatusUpdateDateTime")]
    pub status_update_date_time: chrono::DateTime<chrono::Utc>,
    /// The OB Permissions granted.
    pub permissions: Vec<String>,
    /// The ExpirationDateTime (absent for the default window).
    #[serde(rename = "ExpirationDateTime", skip_serializing_if = "Option::is_none")]
    pub expiration_date_time: Option<chrono::DateTime<chrono::Utc>>,
    /// The consent body's TransactionFrom/To (absent when unset).
    #[serde(
        rename = "TransactionFromDateTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_from_date_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(
        rename = "TransactionToDateTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_to_date_time: Option<chrono::DateTime<chrono::Utc>>,
}

// ── The AppState ───────────────────────────────────────────────────────

/// The UK adapter's application state (the EU adapter's shape): the
/// kernel profile + the pool + the Shield engine + the auth client + the
/// proxy-lane transports + the OB version + the Directory-JWKS trust
/// state.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub profile: Profile,
    /// The shell-booted policy engine (step 5 - the ONLY gate).
    pub policy: std::sync::Arc<PolicyEngine>,
    /// The shared auth client (steps 1-4).
    pub auth_client: sentin8::auth::client::Client,
    /// The Ledger proxy transport (workload `openfin8-uk-ledger`; None
    /// until the boot mint - the proxy lanes 503 loudly).
    pub ledger_http: Option<reqwest::Client>,
    /// The Ledger base URL.
    pub ledger_url: String,
    /// The Payments proxy transport (workload `openfin8-uk-payments`).
    pub payments_http: Option<reqwest::Client>,
    /// The Payments base URL.
    pub payments_url: String,
    /// The served OBL R/W API version (from the profile: default
    /// `3.1.11`, `4.0.1` configurable via `OPENFIN8_UK_VERSION`).
    pub ob_version: String,
    /// The provider route prefix: `/open-banking/v{maj}.{min}` (note
    /// maj.min, unlike FDX's v{major} - UK DESIGN §2).
    pub provider_prefix: String,
    /// The OB Directory JWKS URL (the trust anchor; unavailability
    /// fails closed - 503, never skip-verify).
    pub directory_jwks_url: String,
    /// The ASPSP signing-key reference (`sentin8-secrets://...` - PS256;
    /// never key material in an env var).
    pub signing_key_ref: Option<String>,
    env_id_cell: std::sync::Arc<std::sync::OnceLock<uuid::Uuid>>,
}

impl AppState {
    /// The provider prefix from the OB version: `3.1.11` →
    /// `/open-banking/v3.1` (the maj.min form - the OBL path shape).
    pub fn ob_prefix(version: &str) -> String {
        let mut it = version.split('.');
        let maj = it.next().unwrap_or("3");
        let min = it.next().unwrap_or("1");
        format!("/open-banking/v{maj}.{min}")
    }

    /// Build the state from the shell core + the boot-built lanes.
    pub fn from_core(
        core: sentin8::shell::ServiceCore,
        profile: Profile,
        ledger_http: Option<reqwest::Client>,
        ledger_url: String,
        payments_http: Option<reqwest::Client>,
        payments_url: String,
    ) -> Self {
        let ob_version = profile.fdx_version.clone();
        let provider_prefix = Self::ob_prefix(&ob_version);
        let directory_jwks_url =
            std::env::var("OPENFIN8_UK_DIRECTORY_JWKS_URL").unwrap_or_else(|_| {
                "https://keystore.openbanking.org.uk/001556E127D55D610D5A4F4F0A4A829D47.jwks".into()
            });
        let signing_key_ref = std::env::var("OPENFIN8_UK_SIGNING_KEY_REF").ok();
        Self {
            pool: core.pool.clone(),
            policy: core.admin.policy.clone(),
            auth_client: core.config.sentin8_auth_client.clone(),
            ledger_http,
            ledger_url,
            payments_http,
            payments_url,
            profile,
            ob_version,
            provider_prefix,
            directory_jwks_url,
            signing_key_ref,
            env_id_cell: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// The Ledger proxy transport.
    pub fn ledger_http(&self) -> Option<&reqwest::Client> {
        self.ledger_http.as_ref()
    }

    /// The Payments proxy transport.
    pub fn payments_http(&self) -> Option<&reqwest::Client> {
        self.payments_http.as_ref()
    }

    /// The request-scoped env id.
    pub fn env_id(&self) -> Uuid {
        *self.env_id_cell.get_or_init(Uuid::nil)
    }

    /// The Shield gate (steps 1-5): verify the bearer + evaluate the
    /// action (step 5, the ONLY authorization decision).
    pub async fn authorize(
        &self,
        headers: &axum::http::HeaderMap,
        resource_action: &str,
    ) -> Result<AuthContext, (StatusCode, String)> {
        let a = sentin8::auth::client::verify_bearer_token(&self.auth_client, headers).await?;
        let target = EvalTarget::new(format!("{}:{}", self.profile.service_type, resource_action));
        sentin8::shield::runtime::require_policy(&self.policy, &a, headers, target).await?;
        let _ = self.env_id_cell.set(a.env_id());
        stamp_env_id(a.env_id());
        Ok(a)
    }
}

thread_local! {
    /// The request-scoped env id (the gate stamps it before the handler
    /// runs).
    static ENV_ID: std::cell::Cell<Uuid> = const { std::cell::Cell::new(Uuid::nil()) };
}

/// Stamp the request-scoped env id (the gate calls this).
pub fn stamp_env_id(env_id: Uuid) {
    ENV_ID.with(|c| c.set(env_id));
}

/// The request-scoped env id (the gate stamped it; a nil stamp matches
/// nothing under RLS - the policies enforce env scoping regardless).
pub fn uuid_env() -> Uuid {
    ENV_ID.with(|c| c.get())
}

/// The Shield gate for the resource modules.
pub async fn authorize(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    resource_action: &str,
) -> Result<AuthContext, (StatusCode, String)> {
    state.authorize(headers, resource_action).await
}

// ── The emit path (the outbox contract, same-tx as the domain change) ──

/// Set the transaction-local RLS tenant context (the platform contract;
/// the stream-family arg is `openfin8-uk`).
pub async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'openfin8-uk')",
    )
    .bind(env_id)
    .execute(conn)
    .await;
}

/// Emit a bus event through the local outbox ON THE DOMAIN TRANSACTION
/// (the platform contract: `insert_outbox_row` in the SAME transaction
/// as the domain change). Stream family `openfin8-uk`; event grammar
/// `openfin8:uk:*`.
pub async fn emit_event_pub(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    resource_operation: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sentin8::bus::outbox::insert_outbox_row(
        &mut *conn,
        env_id,
        "openfin8-uk",
        &format!("openfin8:uk:{resource_operation}"),
        &payload,
    )
    .await
    .map(|_| ())
    .map_err(|e| match e {
        sentin8::bus::outbox::OutboxError::Db(db) => db,
        other => sqlx::Error::Protocol(format!("outbox insert: {other}")),
    })
}

async fn emit_event(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    resource_operation: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    emit_event_pub(conn, env_id, resource_operation, payload).await
}

// ── The intent staging + lifecycle routes ───────────────────────────────

/// Stage an OB consent intent (the role/resource pair picks the route
/// the handler binds - aisp/pisp/cbpii). Called on a `client_credentials`
/// token (TPP identification only - never a PSU token; UK invariant 2).
pub async fn stage_consent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    role: &str,
    resource: &str,
    req: &StageConsentRequest,
) -> Result<(StatusCode, ConsentResponse), (StatusCode, String)> {
    validate_role_resource(role, resource).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_permissions(&req.permissions).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // The staging gate: the consent-resource write (the TPP identity).
    let a = authorize(state, headers, "consents:write").await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let expiration = req
        .expiration_date_time
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let tx_from = req
        .transaction_from_date_time
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let tx_to = req
        .transaction_to_date_time
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    // THE INTENT: the staged consent resource serialized verbatim.
    let intent_payload = serde_json::json!({
        "permissions": req.permissions,
        "expiration_date_time": req.expiration_date_time,
        "transaction_from_date_time": req.transaction_from_date_time,
        "transaction_to_date_time": req.transaction_to_date_time,
        "risk": req.risk,
    });
    // The staged-intent expiry: OBL - un-authorized intents die at 24h.
    let staged_expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
    let row = sqlx::query(
        r#"INSERT INTO openfin8_uk.consents
               (env_id, customer_id, recipient_id, status, role, resource,
                permissions, intent_payload, expires_at, staged_expires_at)
           VALUES ($1, NULL, $2, 'awaiting_authorization', $3, $4, $5, $6, $7, $8)
           RETURNING id, created_at, updated_at"#,
    )
    .bind(a.env_id())
    .bind(a.claims.sub.as_str())
    .bind(role)
    .bind(resource)
    .bind(&req.permissions)
    .bind(&intent_payload)
    .bind(expiration)
    .bind(staged_expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let consent_id: Uuid = row.get("id");
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    emit_event(
        &mut tx,
        a.env_id(),
        "consent:created",
        serde_json::json!({
            "consent_id": consent_id,
            "role": role,
            "resource": resource,
            "status": OB_AWAITING,
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        ConsentResponse {
            consent_id,
            creation_date_time: created_at,
            status: OB_AWAITING.to_string(),
            status_update_date_time: created_at,
            permissions: req.permissions.clone(),
            expiration_date_time: expiration,
            transaction_from_date_time: tx_from,
            transaction_to_date_time: tx_to,
        },
    ))
}

/// Read one staged/granted consent (the GET consent resource).
pub async fn read_consent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    consent_id: Uuid,
) -> Result<ConsentResponse, (StatusCode, String)> {
    let a = authorize(state, headers, "consents:read").await?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        r#"SELECT id, status, permissions, expires_at, created_at, updated_at,
                  intent_payload->>'transaction_from_date_time' AS tx_from,
                  intent_payload->>'transaction_to_date_time' AS tx_to
             FROM openfin8_uk.consents WHERE id = $1"#,
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((
        StatusCode::BAD_REQUEST,
        "unknown consent id - the OBL rule: 400".into(),
    ))?;
    let _ = a;
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let tx_from = row
        .get::<Option<String>, _>("tx_from")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let tx_to = row
        .get::<Option<String>, _>("tx_to")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    Ok(ConsentResponse {
        consent_id,
        creation_date_time: created_at,
        status: row.get("status"),
        status_update_date_time: updated_at,
        permissions: row.get("permissions"),
        expiration_date_time: row.get("expires_at"),
        transaction_from_date_time: tx_from,
        transaction_to_date_time: tx_to,
    })
}

/// The TPP DELETE consent (or the PSU revocation through the bank's
/// channels) - both land on the terminal-revocation record; subsequent
/// reads answer 400 (the OBL wire behavior).
pub async fn revoke_consent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    consent_id: Uuid,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = authorize(state, headers, "consents:write").await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let status: String =
        sqlx::query_scalar("SELECT status FROM openfin8_uk.consents WHERE id = $1 FOR UPDATE")
            .bind(consent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::BAD_REQUEST,
                "unknown consent id - the OBL rule: 400".into(),
            ))?;
    let next = consent_transition(&status, "revoke").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("the consent is already terminal ({status})"),
        )
    })?;
    sqlx::query("UPDATE openfin8_uk.consents SET status = $2, updated_at = now() WHERE id = $1")
        .bind(consent_id)
        .bind(&next)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_event(
        &mut tx,
        a.env_id(),
        "consent:revoked",
        serde_json::json!({ "consent_id": consent_id, "status": next }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// The authorization observation (the PSU journey's completion): the
/// intent moves `AwaitingAuthorisation → Authorised` (or `Rejected` on
/// the deny). SCA/authorization success is never conflated with any
/// direct data access - the token binding does that at the middleware.
pub async fn observe_authorization(
    state: &AppState,
    consent_id: Uuid,
    event: &str, // "psu_authorised" | "psu_denied"
    customer_id: Option<Uuid>,
) -> Result<String, (StatusCode, String)> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, uuid_env()).await;
    let status: String =
        sqlx::query_scalar("SELECT status FROM openfin8_uk.consents WHERE id = $1 FOR UPDATE")
            .bind(consent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((
                StatusCode::BAD_REQUEST,
                "unknown consent id - the OBL rule: 400".into(),
            ))?;
    let next = consent_transition(&status, event).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("illegal consent transition: {status} + {event}"),
        )
    })?;
    sqlx::query(
        "UPDATE openfin8_uk.consents \
            SET status = $2, customer_id = COALESCE($3, customer_id), updated_at = now() \
          WHERE id = $1",
    )
    .bind(consent_id)
    .bind(&next)
    .bind(customer_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_event(
        &mut tx,
        uuid_env(),
        "consent:authorisation",
        serde_json::json!({ "consent_id": consent_id, "event": event, "status": next }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(next)
}

/// The data-call consent check: load the intent-bound consent + the
/// verdict (the chokepoint; `Authorised` serves, everything else 400 -
/// the OBL error semantics).
pub async fn require_authorised_consent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    consent_id: Uuid,
    required_permission: Option<&str>,
) -> Result<Vec<String>, (StatusCode, String)> {
    authorize(state, headers, "consents:read").await?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        "SELECT status, permissions, expires_at FROM openfin8_uk.consents WHERE id = $1",
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((
        StatusCode::BAD_REQUEST,
        "unknown consent id - the OBL rule: 400".to_string(),
    ))?;
    let status: String = row.get("status");
    read_verdict(&status).map_err(|(code, msg)| {
        (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            msg.to_string(),
        )
    })?;
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
    if expires_at.map(|e| e < chrono::Utc::now()).unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "the consent's expiration has elapsed".into(),
        ));
    }
    let permissions: Vec<String> = row.get("permissions");
    if let Some(required) = required_permission {
        if !permissions.iter().any(|p| p == required) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("the consent does not carry the permission '{required}'"),
            ));
        }
    }
    Ok(permissions)
}

/// The staged-intent expiry sweep (OBL - un-authorized intents
/// die at 24h; the cron proxy-calls this endpoint on the declared
/// schedule). The expired intents move `AwaitingAuthorisation →
/// Rejected` through the pure table (terminal; a PSU arriving late
/// cannot authorize a dead intent).
#[utoipa::path(
    post,
    path = "/v1/internal/sweep/staged-intents",
    responses(
        (status = 204, description = "The expired staged intents rejected (no content)"),
    ),
    security(),
    tag = "internal",
)]
pub async fn sweep_staged_intents(
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, state.env_id()).await;
    let expired: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE openfin8_uk.consents \
            SET status = 'rejected', updated_at = now() \
          WHERE status = 'awaiting_authorization' AND staged_expires_at < now() \
          RETURNING id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for id in &expired {
        emit_event(
            &mut tx,
            state.env_id(),
            "consent:staged-expired",
            serde_json::json!({ "consent_id": id, "reason": "staged-intent expiry (24h)" }),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(count = expired.len(), "staged-intent expiry sweep complete");
    Ok(StatusCode::NO_CONTENT)
}

// ── The OB route handlers (the router binds them per role) ───────────

/// `POST .../aisp/account-access-consents` - stage the AIS intent (the
/// client-credentials staging; the OB consent body - the codec unwraps
/// `Data`/`Risk`).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/aisp/account-access-consents",
    request_body = StageConsentRequest,
    responses(
        (status = 201, description = "The staged consent (AwaitingAuthorisation)"),
        (status = 400, description = "Field/permission errors"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn stage_aisp_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let data = crate::envelope::unwrap_request(&body);
    let req: StageConsentRequest =
        serde_json::from_value(data).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (code, resp) =
        stage_consent(&state, &headers, ROLE_AISP, RESOURCE_ACCOUNT_ACCESS, &req).await?;
    let mut doc = serde_json::to_value(resp).unwrap_or_default();
    // The OB wire: the staged consent's response shape.
    doc["Risk"] = req.risk.clone();
    Ok((code, Json(doc)))
}

/// `GET .../aisp/account-access-consents/{consentId}` - read the staged
/// consent (the intent status).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/aisp/account-access-consents/{consentId}",
    responses(
        (status = 200, description = "The consent document"),
        (status = 400, description = "Unknown consent id (the OBL rule: 400)"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn get_aisp_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let resp = read_consent(&state, &headers, consent_id).await?;
    let mut doc = serde_json::to_value(resp).unwrap_or_default();
    doc["Risk"] = serde_json::json!({});
    Ok(Json(doc))
}

/// `DELETE .../aisp/account-access-consents/{consentId}` - the TPP
/// revocation (terminal; subsequent reads answer 400).
#[utoipa::path(
    delete,
    path = "/open-banking/v3.1/aisp/account-access-consents/{consentId}",
    responses(
        (status = 204, description = "The consent revoked (no content)"),
        (status = 400, description = "Unknown consent id (the OBL rule: 400)"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn delete_aisp_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    revoke_consent(&state, &headers, consent_id).await
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ob_consent_machine() {
        // Staging → authorized (the PSU journey).
        assert_eq!(
            consent_transition(OB_AWAITING, "psu_authorised").unwrap(),
            OB_AUTHORISED
        );
        // Staging → rejected (the deny or the 24h staged expiry).
        assert_eq!(
            consent_transition(OB_AWAITING, "psu_denied").unwrap(),
            OB_REJECTED
        );
        assert_eq!(
            consent_transition(OB_AWAITING, "staged_expired").unwrap(),
            OB_REJECTED
        );
        // Authorized → consumed (a one-time consent).
        assert_eq!(
            consent_transition(OB_AUTHORISED, "consumed").unwrap(),
            OB_CONSUMED
        );
        // Revocation is terminal from any non-revoked state.
        assert_eq!(
            consent_transition(OB_AWAITING, "revoke").unwrap(),
            OB_REVOKED
        );
        assert_eq!(
            consent_transition(OB_AUTHORISED, "revoke").unwrap(),
            OB_REVOKED
        );
        // Terminal states never leave.
        assert_eq!(consent_transition(OB_REVOKED, "psu_authorised"), None);
        assert_eq!(consent_transition(OB_REJECTED, "psu_authorised"), None);
        assert_eq!(consent_transition(OB_CONSUMED, "consumed"), None);
        // No direct assertion path (the observation only).
        assert_eq!(consent_transition(OB_AWAITING, "consumed"), None);
    }

    #[test]
    fn the_obl_read_verdict() {
        // Only Authorised serves.
        assert!(read_verdict(OB_AUTHORISED).is_ok());
        // Everything else answers 400 (the OBL rule - never a bare 404).
        for s in [OB_AWAITING, OB_REJECTED, OB_CONSUMED, OB_REVOKED] {
            let (code, _) = read_verdict(s).unwrap_err();
            assert_eq!(code, 400, "{s} must answer 400");
        }
        // The revoked text names the dead-consent rule.
        let (_, msg) = read_verdict(OB_REVOKED).unwrap_err();
        assert!(msg.contains("400"));
    }

    #[test]
    fn role_resource_pairing() {
        assert!(validate_role_resource(ROLE_AISP, RESOURCE_ACCOUNT_ACCESS).is_ok());
        assert!(validate_role_resource(ROLE_PISP, RESOURCE_DOMESTIC_PAYMENT).is_ok());
        assert!(validate_role_resource(ROLE_PISP, RESOURCE_DOMESTIC_VRP).is_ok());
        assert!(validate_role_resource(ROLE_CBPII, RESOURCE_FUNDS_CONFIRMATION).is_ok());
        assert!(validate_role_resource(ROLE_AISP, RESOURCE_DOMESTIC_PAYMENT).is_err());
        assert!(validate_role_resource(ROLE_CBPII, RESOURCE_ACCOUNT_ACCESS).is_err());
    }

    #[test]
    fn the_permission_vocabulary() {
        assert!(validate_permissions(&["ReadAccountsBasic".into()]).is_ok());
        assert!(validate_permissions(&["ReadAccountsBasic".into(), "ReadBalances".into()]).is_ok());
        // Empty rejects; unknown rejects (never grants).
        assert!(validate_permissions(&[]).is_err());
        assert!(validate_permissions(&["ReadEverything".into()]).is_err());
    }

    #[test]
    fn the_ob_prefix_is_maj_min() {
        // 3.1.11 → /open-banking/v3.1 (the OBL path shape, unlike FDX's
        // v{major}).
        assert_eq!(AppState::ob_prefix("3.1.11"), "/open-banking/v3.1");
        assert_eq!(AppState::ob_prefix("4.0.1"), "/open-banking/v4.0");
    }
}
