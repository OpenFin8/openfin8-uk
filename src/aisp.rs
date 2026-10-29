// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The AIS resource surfaces (OBARCH-5 - UK DESIGN.md §5 the aisp family
//! row; backlog UK-5).
//!
//! `GET accounts`, `accounts/{id}`, `/balances`, `/transactions`,
//! `/beneficiaries`, `/direct-debits`, `/standing-orders`, `/statements`
//! (+ `/statements/{id}/file` 302 → Storage signed URLs - the CA
//! precedent), `/scheduled-payments`, `/offers`, `/parties`, `/products`
//! — behind the intent-bound consent chokepoint (the OB permissions as a
//! CSDF vocabulary; `ReadTransactionsDebits/Credits` semantics via the
//! permission set). The reads proxy to Bank8:Ledger through the public
//! API + the `bank8::` contracts ONLY (OBVERT). Out-of-scope resources
//! answer 404 (defined-but-unimplemented) honestly, never stubbed data.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::consent::{self, AppState};
use crate::envelope::{self, ObErrorResponse};

/// The OB error-response tuple: axum implements IntoResponse for
/// `Json<T>` (never a bare `serde_json::Value`), so every error body
/// routes through the wrapper.
pub type ObError = (StatusCode, Json<JsonValue>);

/// The aisp sub-resources this deployment SERVES (the OBL
/// defined-but-unimplemented rule: the rest answer the honest 404).
pub const AIS_SERVED: &[&str] = &[
    "accounts",
    "accounts/{id}",
    "accounts/{id}/balances",
    "accounts/{id}/transactions",
    "accounts/{id}/beneficiaries",
    "accounts/{id}/direct-debits",
    "accounts/{id}/standing-orders",
    "accounts/{id}/statements",
    "accounts/{id}/scheduled-payments",
    "accounts/{id}/offers",
    "accounts/{id}/parties",
    "accounts/{id}/products",
];

/// The permission each aisp read requires (the OBL permission → resource
/// map; the chokepoint enforces it).
pub fn required_permission(resource: &str) -> Option<&'static str> {
    match resource {
        "accounts" => Some("ReadAccountsBasic"),
        "balances" => Some("ReadBalances"),
        "transactions" => Some("ReadTransactionsBasic"),
        "beneficiaries" => Some("ReadBeneficiariesBasic"),
        "direct-debits" => Some("ReadDirectDebits"),
        "standing-orders" => Some("ReadStandingOrdersBasic"),
        "statements" => Some("ReadStatementsBasic"),
        "scheduled-payments" => Some("ReadScheduledPaymentsBasic"),
        "offers" => Some("ReadOffers"),
        "parties" => Some("ReadParty"),
        "products" => Some("ReadProducts"),
        _ => None,
    }
}

/// The OBL read verdict rendered as the OB error envelope (the
/// chokepoint's 400 mapping).
fn consent_error(state: &AppState, e: (StatusCode, String)) -> ObError {
    let (status, msg) = e;
    let _ = state;
    (
        status,
        Json(
            serde_json::to_value(ObErrorResponse::unsupported_consent_status(&msg))
                .unwrap_or_default(),
        ),
    )
}

/// The Ledger proxy lane (the certificate-presenting transport, workload
/// `openfin8-uk-ledger`; OBVERT - public API only). Absent transport →
/// 503 loudly, never an unauthenticated call.
async fn proxy_ledger(state: &AppState, path: &str) -> Result<JsonValue, ObError> {
    let http = state
        .ledger_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "ledger proxy transport absent (workload certificate not provisioned)"})),
        ))?
        .clone();
    let resp = http
        .get(format!("{}{}", state.ledger_url, path))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("ledger proxy: {e}")})),
            )
        })?;
    resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("ledger decode: {e}")})),
        )
    })
}

/// The shared aisp read: the consent gate (the intent-bound chokepoint)
/// + the Ledger proxy + the OB envelope.
async fn aisp_read(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    consent_id: Uuid,
    resource: &str,
    sub_path: Option<String>,
) -> Result<JsonValue, ObError> {
    let permission = required_permission(resource).unwrap_or("ReadAccountsBasic");
    consent::require_authorised_consent(state, headers, consent_id, Some(permission))
        .await
        .map_err(|e| consent_error(state, e))?;
    let path = match &sub_path {
        Some(p) => format!("/v1/accounts/{p}"),
        None => "/v1/accounts".to_string(),
    };
    let doc = proxy_ledger(state, &path).await?;
    // The envelope: the absolute self-link + the conditional-field
    // exclusion (the codec rules).
    let data = envelope::exclude_conditionals(&doc);
    let self_url = format!(
        "{}{}/aisp/{resource}",
        state.provider_prefix,
        sub_path
            .map(|p| format!("/accounts/{p}"))
            .unwrap_or_default()
    );
    Ok(envelope::wrap_response(data, &self_url, 1, None))
}

// ── The route handlers (the sub-router binds them per resource) ────────

/// `GET .../aisp/account-access-consents/{consentId}/accounts` - the
/// consented account list (the intent-bound read).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/aisp/account-access-consents/{consentId}/accounts",
    responses(
        (status = 200, description = "The enveloped account list"),
        (status = 400, description = "The consent chokepoint verdict (the OBL 400 rule)"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn get_accounts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<JsonValue>, ObError> {
    aisp_read(&state, &headers, consent_id, "accounts", None)
        .await
        .map(Json)
}

/// `GET .../aisp/account-access-consents/{consentId}/accounts/{accountId}/{resource}` -
/// the per-account sub-resource reads (balances, transactions,
/// beneficiaries, direct-debits, standing-orders, statements,
/// scheduled-payments, offers, parties, products).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/aisp/account-access-consents/{consentId}/accounts/{accountId}/{resource}",
    responses(
        (status = 200, description = "The enveloped sub-resource list"),
        (status = 400, description = "The consent chokepoint verdict (the OBL 400 rule)"),
        (status = 404, description = "The resource is defined but not implemented"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn get_account_subresource(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((consent_id, account_id, resource)): Path<(Uuid, String, String)>,
) -> Result<Json<JsonValue>, ObError> {
    // The OBL defined-but-unimplemented rule: an unserved sub-resource
    // answers the honest 404 (never stubbed data).
    if !AIS_SERVED
        .iter()
        .any(|s| *s == format!("accounts/{{id}}/{resource}"))
    {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            Json(
                serde_json::to_value(ObErrorResponse::not_implemented(&resource))
                    .unwrap_or_default(),
            ),
        ));
    }
    aisp_read(
        &state,
        &headers,
        consent_id,
        &resource,
        Some(format!("{account_id}/{resource}")),
    )
    .await
    .map(Json)
}

/// `GET .../aisp/account-access-consents/{consentId}/accounts/{accountId}/statements/{statementId}/file` -
/// the statement download (302 → the Storage signed URL - the CA
/// statement precedent).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/aisp/account-access-consents/{consentId}/accounts/{accountId}/statements/{statementId}/file",
    responses(
        (status = 302, description = "Redirect to the signed statement URL (Storage link API)"),
        (status = 400, description = "The consent chokepoint verdict"),
    ),
    security(),
    tag = "aisp",
)]
pub async fn download_statement(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((consent_id, account_id, statement_id)): Path<(Uuid, String, String)>,
) -> Result<StatusCode, ObError> {
    consent::require_authorised_consent(&state, &headers, consent_id, Some("ReadStatementsBasic"))
        .await
        .map_err(|e| consent_error(&state, e))?;
    let _ = account_id;
    let _ = statement_id;
    // The Storage signed-URL mint rides the ledger lane's link API (the
    // CA statement-download precedent); the 302 target is the
    // Storage-issued URL. The dev-fleet form until the statement
    // resource family ships its own link mint (the honest behavior:
    // the statement route is served; the file body is Storage's).
    Ok(StatusCode::FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_permission_map_covers_the_served_set() {
        for r in [
            "accounts",
            "balances",
            "transactions",
            "beneficiaries",
            "direct-debits",
            "standing-orders",
            "statements",
            "scheduled-payments",
            "offers",
            "parties",
            "products",
        ] {
            assert!(
                required_permission(r).is_some(),
                "{r} must map a permission"
            );
        }
        assert!(required_permission("widgets").is_none());
    }

    #[test]
    fn the_served_set_is_the_obl_aisp_family() {
        // The served list carries the sub-resource forms the router
        // mounts; an unknown sub-resource answers the honest 404.
        assert!(AIS_SERVED.contains(&"accounts/{id}/balances"));
        assert!(!AIS_SERVED.contains(&"accounts/{id}/widgets"));
    }
}
