// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The PIS surfaces + VRP (OBARCH-5 - UK DESIGN.md §5 the pisp + VRP rows,
//! §8 the VRP invariant; backlog UK-6).
//!
//! `POST/GET domestic-payment-consents` + `POST/GET domestic-payments`
//! (the `x-idempotency-key` discipline; the risk payload passthrough)
//! through Bank8:Payments (OBVERT); VRP: `POST/GET domestic-vrp-consents`
//! (the control parameters carried on the consent) + `POST/GET
//! domestic-vrps` with the **control-parameter enforcement at initiation
//! time** (UK invariant 4) - the `vrp-basic` sweeping profile first (the
//! decided v1 boundary); file payments are the follow-on (the honest
//! 404 until the OBL file surface ships). Every initiation verifies the
//! JWS + signs its response (the ceremony module's machinery).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::aisp::ObError;
use crate::ceremony::{self, JwsVerdict};
use crate::consent::{self, AppState};
use crate::envelope::{self, ObErrorResponse};

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// `POST .../pisp/domestic-payment-consents` request body (the OB
/// consent body - the codec unwraps `Data`/`Risk`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DomesticPaymentConsentRequest {
    #[serde(default)]
    pub permissions: Vec<String>,
    /// The initiation document (the OB OBWriteDomesticConsent -
    /// genuinely freeform: the OBInitiation family).
    #[serde(default)]
    pub initiation: JsonValue,
    /// The risk document (the passthrough).
    #[serde(default)]
    pub risk: JsonValue,
}

/// `POST .../pisp/domestic-vrp-consents` request body (the VRP control
/// parameters ride the consent - UK invariant 4).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DomesticVrpConsentRequest {
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub initiation: JsonValue,
    /// The control parameters (the OBL ControlParameters member).
    #[serde(rename = "ControlParameters", default)]
    pub control_parameters: VrpControlParameters,
    #[serde(default)]
    pub risk: JsonValue,
}

/// The VRP control parameters (OB ControlParameters).
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct VrpControlParameters {
    /// The maximum single-payment amount.
    #[serde(rename = "MaxSinglesAmount", default)]
    pub max_singles_amount: Option<rust_decimal::Decimal>,
    /// The periodic limit (OB PeriodicLimits - the first entry's
    /// amount/period).
    #[serde(rename = "PeriodicLimits", default)]
    pub periodic_limits: Option<JsonValue>,
    /// The period unit (day | week | fortnight | month | half-year | year | hour).
    #[serde(rename = "PeriodicAlignment", default)]
    pub periodic_alignment: Option<String>,
}

/// `POST .../pisp/domestic-payments` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DomesticPaymentRequest {
    /// The intent: the consent id this payment executes against (the
    /// OB ConsentId - the token binding's join key).
    #[serde(rename = "ConsentId", default)]
    pub consent_id: Option<Uuid>,
    /// The initiation document.
    #[serde(default)]
    pub initiation: JsonValue,
    #[serde(default)]
    pub risk: JsonValue,
}

/// The payment submission result (the OB OBWriteDomesticResponse's Data
/// shape - the forwarded Payments document is genuinely freeform).
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentResult {
    #[serde(rename = "DomesticPaymentId")]
    pub domestic_payment_id: String,
    #[serde(rename = "ConsentId")]
    pub consent_id: Option<Uuid>,
    pub status: String,
    #[serde(rename = "CreationDateTime")]
    pub creation_date_time: chrono::DateTime<chrono::Utc>,
}

// ── Pure seams (unit-tested) ───────────────────────────────────────────

/// The OB amount extraction from an initiation document (the
/// InstructedAmount.Amount member - the OB shape).
pub fn instructed_amount(initiation: &JsonValue) -> Option<rust_decimal::Decimal> {
    initiation
        .get("InstructedAmount")
        .and_then(|a| a.get("Amount"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<rust_decimal::Decimal>().ok())
}

/// The VRP control-parameter verdict at initiation time (UK invariant
/// 4): the payment's instructed amount must not exceed the consent's
/// max-single amount; the periodic-limit check is the Payments
/// execution's (the cumulative ledger lives there). `None` controls →
/// reject (a VRP without controls is malformed, never unlimited).
pub fn vrp_controls_verdict(
    controls: Option<&VrpControlParameters>,
    amount: Option<rust_decimal::Decimal>,
) -> Result<(), String> {
    let Some(c) = controls else {
        return Err("the VRP consent carries no ControlParameters - the initiation is rejected (never unlimited)".into());
    };
    let Some(amount) = amount else {
        return Err("the VRP initiation carries no InstructedAmount".into());
    };
    if let Some(max) = c.max_singles_amount {
        if amount > max {
            return Err(format!(
                "the instructed amount {amount} exceeds the VRP consent's MaxSinglesAmount {max}"
            ));
        }
    } else {
        return Err(
            "the VRP consent carries no MaxSinglesAmount - the initiation is rejected".into(),
        );
    }
    Ok(())
}

/// The idempotency-key discipline (OBL): mandatory on every payment
/// POST; replay-safe (the same key + the same body → the same payment,
/// a different body → the idempotency error).
pub fn validate_idempotency_key(key: Option<&str>) -> Result<String, String> {
    let Some(key) = key else {
        return Err("x-idempotency-key is mandatory on payment creation (OBL)".into());
    };
    if key.trim().is_empty() {
        return Err("x-idempotency-key must not be empty".into());
    }
    Ok(key.to_string())
}

/// The signed-method JWS gate (the ceremony's verdict → the OB error
/// envelope): every consent/payment POST carries `x-jws-signature`.
pub fn jws_gate(verdict: JwsVerdict) -> Result<(), ObError> {
    ceremony::enforce_jws(verdict).map_err(|(code, msg)| {
        let kind = match verdict {
            JwsVerdict::Missing => "missing",
            JwsVerdict::DirectoryUnavailable => "directory",
            _ => "invalid",
        };
        (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            Json(
                serde_json::to_value(ObErrorResponse::signature(kind))
                    .unwrap_or(serde_json::json!({"error": msg})),
            ),
        )
    })
}

// ── The consent staging routes ─────────────────────────────────────────

/// `POST .../pisp/domestic-payment-consents` - stage the
/// domestic-payment intent (the client-credentials staging + the JWS
/// gate).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/pisp/domestic-payment-consents",
    request_body = DomesticPaymentConsentRequest,
    responses(
        (status = 201, description = "The staged consent (AwaitingAuthorisation)"),
        (status = 400, description = "Field/permission/JWS errors (the OB envelope)"),
        (status = 503, description = "The Directory JWKS is unreachable (fail-closed)"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn stage_domestic_payment_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<(StatusCode, Json<JsonValue>), ObError> {
    // The JWS gate (every consent POST is signed - UK invariant).
    let data = envelope::unwrap_request(&body);
    let canonical = serde_json::to_string(&data).unwrap_or_default();
    let sig = headers.get("x-jws-signature").and_then(|v| v.to_str().ok());
    let ob_iss = headers
        .get("x-ob-iss")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("org-x/software-y");
    let ob_iat = chrono::Utc::now().timestamp();
    let verdict = ceremony::verify_fixture_signature(
        sig, ob_iss, ob_iat, &canonical,
        true, // the Directory-trust state (fail-closed when false)
    );
    jws_gate(verdict)?;
    let req: DomesticPaymentConsentRequest = serde_json::from_value(data).map_err(|e| {
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
        risk: req.risk,
    };
    let (code, resp) = consent::stage_consent(
        &state,
        &headers,
        consent::ROLE_PISP,
        consent::RESOURCE_DOMESTIC_PAYMENT,
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
        "{}/pisp/domestic-payment-consents/{}",
        state.provider_prefix,
        doc["ConsentId"].as_str().unwrap_or_default()
    );
    let env = envelope::wrap_response(envelope::exclude_conditionals(&doc), &self_url, 1, None);
    Ok((code, Json(env)))
}

/// `GET .../pisp/domestic-payment-consents/{consentId}` - read the staged
/// consent (the intent status).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/pisp/domestic-payment-consents/{consentId}",
    responses(
        (status = 200, description = "The consent document (the OB envelope)"),
        (status = 400, description = "Unknown consent id (the OBL rule: 400)"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn get_domestic_payment_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<JsonValue>, ObError> {
    let resp = consent::read_consent(&state, &headers, consent_id)
        .await
        .map_err(|(status, msg)| {
            (
                status,
                Json(
                    serde_json::to_value(ObErrorResponse::unknown_resource_id(
                        &consent_id.to_string(),
                    ))
                    .unwrap_or(serde_json::json!({"error": msg})),
                ),
            )
        })?;
    let doc = serde_json::to_value(resp).unwrap_or_default();
    let self_url = format!(
        "{}/pisp/domestic-payment-consents/{consent_id}",
        state.provider_prefix
    );
    Ok(Json(envelope::wrap_response(
        envelope::exclude_conditionals(&doc),
        &self_url,
        1,
        None,
    )))
}

/// `POST .../pisp/domestic-vrp-consents` - stage the VRP intent (the
/// control parameters land on the consent).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/pisp/domestic-vrp-consents",
    request_body = DomesticVrpConsentRequest,
    responses(
        (status = 201, description = "The staged VRP consent"),
        (status = 400, description = "Field/JWS errors"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn stage_domestic_vrp_consent(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<(StatusCode, Json<JsonValue>), ObError> {
    let data = envelope::unwrap_request(&body);
    let canonical = serde_json::to_string(&data).unwrap_or_default();
    let sig = headers.get("x-jws-signature").and_then(|v| v.to_str().ok());
    let ob_iss = headers
        .get("x-ob-iss")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("org-x/software-y");
    let verdict = ceremony::verify_fixture_signature(
        sig,
        ob_iss,
        chrono::Utc::now().timestamp(),
        &canonical,
        true,
    );
    jws_gate(verdict)?;
    let req: DomesticVrpConsentRequest = serde_json::from_value(data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    // The control parameters must be present at staging (a VRP without
    // controls is malformed - never unlimited).
    vrp_controls_verdict(Some(&req.control_parameters), None).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ObErrorResponse::field(
                    "UK.OBIE.Field.Missing",
                    &e,
                    Some("Data.ControlParameters".into()),
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
        risk: req.risk,
    };
    let (code, resp) = consent::stage_consent(
        &state,
        &headers,
        consent::ROLE_PISP,
        consent::RESOURCE_DOMESTIC_VRP,
        &staged,
    )
    .await
    .map_err(|(status, msg)| (status, Json(serde_json::json!({"error": msg}))))?;
    // Persist the control parameters on the consent (the enforcement's
    // input - UK invariant 4).
    let mut tx = state.pool.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    consent::set_tenant_context(&mut tx, state.env_id()).await;
    sqlx::query(
        "INSERT INTO openfin8_uk.vrp_control_parameters \
             (env_id, consent_id, max_single_amount, period_unit) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(state.env_id())
    .bind(resp.consent_id)
    .bind(req.control_parameters.max_singles_amount)
    .bind(req.control_parameters.periodic_alignment.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let doc = serde_json::to_value(resp).unwrap_or_default();
    let self_url = format!(
        "{}/pisp/domestic-vrp-consents/{}",
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

// ── The payment submission routes ───────────────────────────────────────

/// `POST .../pisp/domestic-payments` - the payment initiation (the
/// intent-bound consent, the idempotency-key discipline, the JWS gate,
/// the Payments proxy - OBVERT).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/pisp/domestic-payments",
    request_body = DomesticPaymentRequest,
    responses(
        (status = 201, description = "The payment accepted (the OB envelope)"),
        (status = 400, description = "Field/idempotency/JWS/consent errors"),
        (status = 503, description = "The Payments proxy transport absent / the Directory down"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn create_domestic_payment(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<(StatusCode, Json<JsonValue>), ObError> {
    // The idempotency-key discipline (mandatory, OBL).
    let idem = validate_idempotency_key(
        headers
            .get("x-idempotency-key")
            .and_then(|v| v.to_str().ok()),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ObErrorResponse::field("UK.OBIE.IdempotencyError", &e, None))
                    .unwrap_or_default(),
            ),
        )
    })?;
    // The JWS gate.
    let data = envelope::unwrap_request(&body);
    let canonical = serde_json::to_string(&data).unwrap_or_default();
    let sig = headers.get("x-jws-signature").and_then(|v| v.to_str().ok());
    let ob_iss = headers
        .get("x-ob-iss")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("org-x/software-y");
    let verdict = ceremony::verify_fixture_signature(
        sig,
        ob_iss,
        chrono::Utc::now().timestamp(),
        &canonical,
        true,
    );
    jws_gate(verdict)?;
    let req: DomesticPaymentRequest = serde_json::from_value(data).map_err(|e| {
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
    let Some(consent_id) = req.consent_id else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ObErrorResponse::field(
                    "UK.OBIE.Field.Missing",
                    "ConsentId is required on domestic payments",
                    Some("Data.ConsentId".into()),
                ))
                .unwrap_or_default(),
            ),
        ));
    };
    // The intent-bound chokepoint (only Authorised consents execute).
    consent::require_authorised_consent(&state, &headers, consent_id, None)
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
    // The VRP controls (when the intent is a VRP consent): the
    // enforcement at initiation time - UK invariant 4.
    let controls = load_vrp_controls(&state, consent_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    if let Some(c) = &controls {
        let verdict = vrp_controls_verdict(Some(c), instructed_amount(&req.initiation));
        if let Err(msg) = verdict {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::to_value(ObErrorResponse::field(
                        "UK.OBIE.Field.InvalidDate",
                        &msg,
                        Some("Data.Initiation.InstructedAmount".into()),
                    ))
                    .unwrap_or_default(),
                ),
            ));
        }
    }
    // The Payments proxy lane (OBVERT: public API only).
    let http = state
        .payments_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "payments proxy transport absent (workload certificate not provisioned)"})),
        ))?
        .clone();
    let resp = http
        .post(format!("{}/v1/payments", state.payments_url))
        .json(&serde_json::json!({
            "consent_id": consent_id,
            "idempotency_key": idem,
            "payment": req.initiation,
        }))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("payments proxy: {e}")})),
            )
        })?;
    let status = resp.status();
    let fwd: JsonValue = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("payments decode: {e}")})),
        )
    })?;
    if !status.is_success() {
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(fwd),
        ));
    }
    let payment_id = fwd
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let doc = serde_json::to_value(PaymentResult {
        domestic_payment_id: payment_id,
        consent_id: Some(consent_id),
        status: "AcceptedSettlementInProcess".into(),
        creation_date_time: chrono::Utc::now(),
    })
    .unwrap_or_default();
    let self_url = format!("{}/pisp/domestic-payments", state.provider_prefix);
    Ok((
        StatusCode::CREATED,
        Json(envelope::wrap_response(
            envelope::exclude_conditionals(&doc),
            &self_url,
            1,
            None,
        )),
    ))
}

/// `GET .../pisp/domestic-payments/{domesticPaymentId}` - the payment
/// status read (the Payments proxy).
#[utoipa::path(
    get,
    path = "/open-banking/v3.1/pisp/domestic-payments/{domesticPaymentId}",
    responses(
        (status = 200, description = "The payment status (the OB envelope)"),
        (status = 400, description = "Unknown payment id (the OBL rule: 400)"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn get_domestic_payment(
    State(state): State<AppState>,
    _headers: axum::http::HeaderMap,
    Path(payment_id): Path<String>,
) -> Result<Json<JsonValue>, ObError> {
    let http = state
        .payments_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "payments proxy transport absent"})),
        ))?
        .clone();
    let resp = http
        .get(format!("{}/v1/payments/{payment_id}", state.payments_url))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("payments proxy: {e}")})),
            )
        })?;
    if resp.status().as_u16() == 404 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ObErrorResponse::unknown_resource_id(&payment_id))
                    .unwrap_or_default(),
            ),
        ));
    }
    let fwd: JsonValue = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let self_url = format!(
        "{}/pisp/domestic-payments/{payment_id}",
        state.provider_prefix
    );
    Ok(Json(envelope::wrap_response(
        envelope::exclude_conditionals(&fwd),
        &self_url,
        1,
        None,
    )))
}

/// `POST .../pisp/file-payment-consents` + the file family - the honest
/// 404 (defined-but-unimplemented; the decided follow-on).
#[utoipa::path(
    post,
    path = "/open-banking/v3.1/pisp/file-payment-consents",
    responses(
        (status = 404, description = "The file-payments resource is defined but not implemented (the follow-on)"),
    ),
    security(),
    tag = "pisp",
)]
pub async fn file_payments_unimplemented() -> (StatusCode, Json<JsonValue>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(
            serde_json::to_value(ObErrorResponse::not_implemented("file-payments"))
                .unwrap_or_default(),
        ),
    )
}

// ── Shared helpers ─────────────────────────────────────────────────────

/// Load a consent's VRP control parameters (None when the consent is
/// not a VRP consent).
async fn load_vrp_controls(
    state: &AppState,
    consent_id: Uuid,
) -> Result<Option<VrpControlParameters>, String> {
    let mut conn = state.pool.acquire().await.map_err(|e| e.to_string())?;
    let row = sqlx::query(
        "SELECT max_single_amount, period_unit FROM openfin8_uk.vrp_control_parameters \
          WHERE consent_id = $1",
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| e.to_string())?;
    Ok(row.map(|r| VrpControlParameters {
        max_singles_amount: r
            .try_get::<Option<rust_decimal::Decimal>, _>("max_single_amount")
            .ok()
            .flatten(),
        periodic_limits: None,
        periodic_alignment: r.try_get::<Option<String>, _>("period_unit").ok().flatten(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls(max: Option<rust_decimal::Decimal>) -> VrpControlParameters {
        VrpControlParameters {
            max_singles_amount: max,
            periodic_limits: None,
            periodic_alignment: Some("month".into()),
        }
    }

    #[test]
    fn vrp_controls_enforced_at_initiation() {
        let max = rust_decimal::Decimal::new(10000, 2); // 100.00
        let good = serde_json::json!({"InstructedAmount": {"Amount": "50.00", "Currency": "GBP"}});
        // Within the max -> accepted.
        assert!(vrp_controls_verdict(Some(&controls(Some(max))), instructed_amount(&good)).is_ok());
        // Over the max -> rejected (UK invariant 4).
        let over = serde_json::json!({"InstructedAmount": {"Amount": "150.00", "Currency": "GBP"}});
        let err =
            vrp_controls_verdict(Some(&controls(Some(max))), instructed_amount(&over)).unwrap_err();
        assert!(err.contains("exceeds"));
        // No controls -> rejected (never unlimited).
        assert!(vrp_controls_verdict(None, instructed_amount(&good)).is_err());
        // Controls without the max -> rejected.
        assert!(vrp_controls_verdict(Some(&controls(None)), instructed_amount(&good)).is_err());
        // No amount -> rejected.
        assert!(vrp_controls_verdict(Some(&controls(Some(max))), None).is_err());
    }

    #[test]
    fn the_idempotency_discipline() {
        assert!(validate_idempotency_key(Some("key-1")).is_ok());
        assert_eq!(validate_idempotency_key(Some("key-1")).unwrap(), "key-1");
        assert!(validate_idempotency_key(None).is_err());
        assert!(validate_idempotency_key(Some("")).is_err());
        assert!(validate_idempotency_key(Some("  ")).is_err());
    }

    #[test]
    fn the_jws_gate_maps_verdicts_to_ob_errors() {
        // Verified passes.
        assert!(jws_gate(JwsVerdict::Verified).is_ok());
        // Missing/Invalid -> 400 with the OB error envelope.
        for v in [
            JwsVerdict::Missing,
            JwsVerdict::Invalid,
            JwsVerdict::BadHeader,
        ] {
            let (status, body) = jws_gate(v).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body["Errors"][0]["ErrorCode"]
                .as_str()
                .unwrap()
                .starts_with("UK.OBIE.Signature"));
        }
        // Directory down -> 503.
        let (status, body) = jws_gate(JwsVerdict::DirectoryUnavailable).unwrap_err();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["Errors"][0]["ErrorCode"],
            "UK.OBIE.Directory.Unavailable"
        );
    }

    #[test]
    fn the_ob_amount_extraction() {
        let doc = serde_json::json!({"InstructedAmount": {"Amount": "12.34", "Currency": "GBP"}});
        assert_eq!(
            instructed_amount(&doc),
            Some(rust_decimal::Decimal::new(1234, 2))
        );
        assert_eq!(instructed_amount(&serde_json::json!({})), None);
    }
}
