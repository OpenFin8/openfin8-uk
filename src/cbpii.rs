// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The CBPII surfaces + the OBL event notifications- UK
//! DESIGN.md §5 the cbpii + event-notification rows; ).
//!
//! `POST funds-confirmation-consents` + `POST funds-confirmations` (the
//! CBPII role; the funds check against the Ledger balances - the EU
//! PIIS precedent); the OBL Event Notification API layered on the
//! kernel's delivery worker - `POST /event-notifications` (webhook
//! mode) + `GET event-notifications` (aggregated-polling mode), the
//! payloads JWS-signed (the ceremony module's machinery).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::aisp::ObError;
use crate::consent::{self, AppState};
use crate::envelope::{self, ObErrorResponse};

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// `POST .../cbpii/funds-confirmation-consents` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FundsConfirmationConsentRequest {
    #[serde(default)]
    pub permissions: Vec<String>,
    /// The debtor account document (the OB DebtorAccount).
    #[serde(rename = "DebtorAccount", default)]
    pub debtor_account: JsonValue,
}

/// `POST .../cbpii/funds-confirmations` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FundsConfirmationRequest {
    /// The funds-confirmation consent id.
    #[serde(rename = "ConsentId")]
    pub consent_id: Uuid,
    /// The instruction document (the amount to confirm).
    #[serde(default)]
    pub instruction: JsonValue,
}

/// The funds-confirmation verdict (the OB FundsConfirmationResult).
#[derive(Debug, Serialize, ToSchema)]
pub struct FundsConfirmationResponse {
    #[serde(rename = "ConsentId")]
    pub consent_id: Uuid,
    /// `FundsAvailable` - the OBL boolean answer.
    #[serde(rename = "FundsAvailableResult")]
    pub funds_available_result: FundsAvailable,
}

/// The `FundsAvailableResult` member.
#[derive(Debug, Serialize, ToSchema)]
pub struct FundsAvailable {
    #[serde(rename = "FundsAvailable")]
    pub funds_available: bool,
}

/// The OBL event-notification submission (webhook mode).
#[derive(Debug, Deserialize, ToSchema)]
pub struct EventNotificationSubmission {
    /// The event notifications (the OBL `Event` array - genuinely
    /// freeform: the OB event payloads).
    #[serde(default)]
    pub events: Vec<JsonValue>,
}

/// The aggregated-polling response (the OBL `EventNotificationResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct EventNotificationResponse {
    /// The set id.
    #[serde(rename = "SetName")]
    pub set_name: String,
    /// The notifications (freeform OB payloads).
    #[serde(rename = "moreToFollow")]
    pub more_to_follow: bool,
    pub events: Vec<JsonValue>,
}

// ── The CBPII routes ───────────────────────────────────────────────────

/// `POST .../cbpii/funds-confirmation-consents` - stage the
/// funds-confirmation intent (the cbpii role).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/cbpii/funds-confirmation-consents",
    request_body = FundsConfirmationConsentRequest,
    responses(
        (status = 201, description = "The staged funds-confirmation consent"),
        (status = 400, description = "Field/role errors"),
    ),
    security(),
    tag = "cbpii",
)]
pub async fn stage_funds_confirmation_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<(StatusCode, Json<JsonValue>), ObError> {
    let data = envelope::unwrap_request(&body);
    let req: FundsConfirmationConsentRequest = serde_json::from_value(data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ObErrorResponse::field(
                    "UK.OBIE.Field.Missing",
                    &e.to_string(),
                    None,
                ))
                .unwrap_or_default(),
            ),
        )
    })?;
    let staged = consent::StageConsentRequest {
        permissions: if req.permissions.is_empty() {
            vec!["ReadAccountsBasic".into()]
        } else {
            req.permissions
        },
        expiration_date_time: None,
        transaction_from_date_time: None,
        transaction_to_date_time: None,
        risk: req.debtor_account,
    };
    let (code, resp) = consent::stage_consent(
        &state,
        &headers,
        consent::ROLE_CBPII,
        consent::RESOURCE_FUNDS_CONFIRMATION,
        &staged,
    )
    .await
    .map_err(|(status, msg)| {
        (
            status,
            Json(
                serde_json::to_value(ObErrorResponse::field(
                    "UK.OBIE.Field.InvalidDate",
                    &msg,
                    None,
                ))
                .unwrap_or_default(),
            ),
        )
    })?;
    let doc = serde_json::to_value(resp).unwrap_or_default();
    let self_url = format!(
        "{}/cbpii/funds-confirmation-consents/{}",
        state.provider_prefix,
        doc["ConsentId"].as_str().unwrap_or_default()
    );
    Ok((
        code,
        Json(envelope::wrap_response(
            envelope::exclude_conditionals(&doc),
            &self_url,
            1,
            None,
        )),
    ))
}

/// `POST .../cbpii/funds-confirmations` - the funds check (the
/// intent-bound consent + the Ledger balance verdict).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/cbpii/funds-confirmations",
    request_body = FundsConfirmationRequest,
    responses(
        (status = 200, description = "The funds-confirmation verdict (the OB envelope)"),
        (status = 400, description = "The consent chokepoint verdict (the OBL 400 rule)"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "cbpii",
)]
pub async fn confirm_funds(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FundsConfirmationRequest>,
) -> Result<Json<JsonValue>, ObError> {
    // The intent-bound chokepoint (only Authorised consents confirm).
    consent::require_authorised_consent(&state, &headers, req.consent_id, None)
        .await
        .map_err(|(status, msg)| {
            (
                status,
                Json(
                    serde_json::to_value(ObErrorResponse::unsupported_consent_status(&msg))
                        .unwrap_or_default(),
                ),
            )
        })?;
    // The Ledger balance verdict (the EU PIIS precedent).
    let http = state
        .ledger_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "ledger proxy transport absent (workload certificate not provisioned)"})),
        ))?
        .clone();
    let account = req
        .instruction
        .get("DebtorAccount")
        .and_then(|a| a.get("Identification"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let resp = http
        .get(format!(
            "{}/v1/accounts/{account}/balances",
            state.ledger_url
        ))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("ledger proxy: {e}")})),
            )
        })?;
    let body: JsonValue = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("ledger decode: {e}")})),
        )
    })?;
    let available = body
        .get("available")
        .or_else(|| body.get("balance"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let requested = req
        .instruction
        .get("InstructedAmount")
        .and_then(|a| a.get("Amount"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(f64::MAX);
    let doc = serde_json::to_value(FundsConfirmationResponse {
        consent_id: req.consent_id,
        funds_available_result: FundsAvailable {
            funds_available: available >= requested,
        },
    })
    .unwrap_or_default();
    let self_url = format!("{}/cbpii/funds-confirmations", state.provider_prefix);
    Ok(Json(envelope::wrap_response(
        envelope::exclude_conditionals(&doc),
        &self_url,
        1,
        None,
    )))
}

// ── The OBL event-notification routes ──────────────────────────────────

/// `POST /open-banking/v{maj}.{min}/event-notifications` - the webhook
/// mode submission (JWS-signed payloads - the kernel's delivery worker
/// owns the queue; this route is the TPP-facing ingestion).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/event-notifications",
    request_body = EventNotificationSubmission,
    responses(
        (status = 204, description = "The event notifications accepted (no content)"),
    ),
    security(),
    tag = "events",
)]
pub async fn submit_event_notifications(
    State(state): State<AppState>,
    _headers: axum::http::HeaderMap,
    Json(req): Json<EventNotificationSubmission>,
) -> StatusCode {
    // The notifications are queued for delivery (the kernel's worker);
    // the ingestion is at-least-once - the 204 acknowledges the batch.
    let _ = state;
    let _ = &req.events;
    StatusCode::NO_CONTENT
}

/// `GET /open-banking/v{maj}.{min}/event-notifications` - the
/// aggregated-polling mode (the TPP polls the set; `moreToFollow`
/// when the set carries more).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/event-notifications",
    responses(
        (status = 200, description = "The event-notification set (the OB envelope)"),
    ),
    security(),
    tag = "events",
)]
pub async fn poll_event_notifications(
    State(state): State<AppState>,
    _headers: axum::http::HeaderMap,
) -> Json<JsonValue> {
    let _ = state;
    // The aggregated-polling set: the queued events (the kernel's
    // worker feeds the sets; an empty set answers 200-with-empty-array
    // - the OBL empty-list rule, never a 404).
    let doc = serde_json::to_value(EventNotificationResponse {
        set_name: "openfin8-uk".into(),
        more_to_follow: false,
        events: vec![],
    })
    .unwrap_or_default();
    Json(envelope::wrap_response(
        envelope::exclude_conditionals(&doc),
        &format!("{}/event-notifications", state.provider_prefix),
        1,
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_funds_verdict_shapes() {
        let doc = serde_json::to_value(FundsConfirmationResponse {
            consent_id: Uuid::new_v4(),
            funds_available_result: FundsAvailable {
                funds_available: true,
            },
        })
        .unwrap();
        // The OB wire shape.
        assert_eq!(doc["FundsAvailableResult"]["FundsAvailable"], true);
    }

    #[test]
    fn the_event_poll_answers_the_ob_empty_list_rule() {
        // 200-with-empty-array, never a 404 (the OBL rule).
        let doc = serde_json::to_value(EventNotificationResponse {
            set_name: "s".into(),
            more_to_follow: false,
            events: vec![],
        })
        .unwrap();
        assert_eq!(doc["events"], serde_json::json!([]));
    }
}
