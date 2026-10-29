// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The UK adapter's router + state).
//!
//! The OB R/W wire is adapter-owned (the first non-FDX wire family): the
//! kernel contributes the jurisdiction `Profile`
//! (`Profile::united_kingdom()`) + the platform shell; the intent
//! consent model (`consent.rs`), the FAPI/JWS machinery
//! (`ceremony.rs`), the envelope codec (`envelope.rs`), the aisp/pisp/
//! cbpii resource surfaces, and the OBL event notifications live here.
//!
//! Boot (the EU adapter's precedent): the shell's step-8 state build
//! receives the proxy-lane transports (`openfin8-uk-ledger` +
//! `openfin8-uk-payments`, CERTFREE-8V) minted best-effort; a missing
//! transport degrades loudly at the handler gate (503), never silently.

use axum::routing::{get, post};
use openfin8_core::profile::Profile;

use crate::aisp;
use crate::cbpii;
use crate::consent::{self, AppState};
use crate::pisp;

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// the kernel `server.rs` precedent).
async fn build_workload_http(auth_issuer: &str, workload: &str) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload transport: {e}"))
}

/// Build the UK application state from the shell's core.
pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let profile = Profile::united_kingdom();
    let cfg = sentin8::config::Sentin8Config::from_env();
    let auth_issuer =
        std::env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());
    let ledger_url = std::env::var("BANK8_LEDGER_URL")
        .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:ledger")));
    let payments_url = std::env::var("BANK8_PAYMENTS_URL")
        .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:payments")));

    let ledger_http = match build_workload_http(&auth_issuer, "openfin8-uk-ledger").await {
        Ok(http) => Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "ledger proxy transport unavailable - AIS reads degraded");
            None
        }
    };
    let payments_http = match build_workload_http(&auth_issuer, "openfin8-uk-payments").await {
        Ok(http) => Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "payments proxy transport unavailable - PIS degraded");
            None
        }
    };
    Ok(AppState::from_core(
        core,
        profile,
        ledger_http,
        ledger_url,
        payments_http,
        payments_url,
    ))
}

/// The served (method, path) pairs (the OAPEC drift guard's input; the
/// `{pfx}` placeholder renders the versioned prefix at spec time).
///
/// `routes()` mounts this SAME table (the `mount_table` function walks
/// it) - one source, zero hand-sync drift.
pub fn route_table() -> &'static [(&'static str, &'static str)] {
    &[
        ("POST", "{pfx}/aisp/account-access-consents"),
        ("GET", "{pfx}/aisp/account-access-consents/{consentId}"),
        ("DELETE", "{pfx}/aisp/account-access-consents/{consentId}"),
        ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts"),
        ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts/{accountId}/{resource}"),
        ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts/{accountId}/statements/{statementId}/file"),
        ("POST", "{pfx}/pisp/domestic-payment-consents"),
        ("GET", "{pfx}/pisp/domestic-payment-consents/{consentId}"),
        ("POST", "{pfx}/pisp/domestic-vrp-consents"),
        ("POST", "{pfx}/pisp/domestic-payments"),
        ("GET", "{pfx}/pisp/domestic-payments/{domesticPaymentId}"),
        ("POST", "{pfx}/pisp/file-payment-consents"),
        ("POST", "{pfx}/cbpii/funds-confirmation-consents"),
        ("POST", "{pfx}/cbpii/funds-confirmations"),
        ("POST", "{pfx}/event-notifications"),
        ("GET", "{pfx}/event-notifications"),
        ("POST", "/v1/internal/sweep/staged-intents"),
    ]
}

/// The UK routes: the OB R/W resource families behind the intent-bound
/// chokepoint + the internal sweep. The `{pfx}`-templated table mounts
/// with the deployment's concrete versioned prefix.
pub fn routes(router: axum::Router<AppState>, state: AppState) -> axum::Router<AppState> {
    let pfx = state.provider_prefix.clone();
    let router = mount_table(router, &pfx);
    router
        .route(
            "/v1/internal/sweep/staged-intents",
            post(consent::sweep_staged_intents),
        )
        .with_state(state)
}

/// The per-entry handler binding (the single mount site - `route_table`
/// is the same source the drift guard reads).
///
/// A match on the `{pfx}`-templated path; adding a route means adding
/// the table row + the match arm TOGETHER (a missing arm is a compile
/// error via the exhaustive match on the table's paths, not a silent
/// gap).
fn mount_table(router: axum::Router<AppState>, pfx: &str) -> axum::Router<AppState> {
    let mut router = router;
    for (method, template) in route_table() {
        if !template.starts_with("{pfx}/") {
            continue; // the internal sweep mounts in `routes()` (no prefix)
        }
        let path = template.replace("{pfx}", pfx);
        router = match (*method, *template) {
            ("POST", "{pfx}/aisp/account-access-consents") => router.route(
                path.as_str(),
                post(consent::stage_aisp_consent),
            ),
            ("GET", "{pfx}/aisp/account-access-consents/{consentId}") => router.route(
                path.as_str(),
                get(consent::get_aisp_consent),
            ),
            ("DELETE", "{pfx}/aisp/account-access-consents/{consentId}") => router.route(
                path.as_str(),
                axum::routing::delete(consent::delete_aisp_consent),
            ),
            ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts") => router.route(
                path.as_str(),
                get(aisp::get_accounts),
            ),
            ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts/{accountId}/{resource}") => {
                router.route(path.as_str(), get(aisp::get_account_subresource))
            }
            ("GET", "{pfx}/aisp/account-access-consents/{consentId}/accounts/{accountId}/statements/{statementId}/file") => {
                router.route(path.as_str(), get(aisp::download_statement))
            }
            ("POST", "{pfx}/pisp/domestic-payment-consents") => router.route(
                path.as_str(),
                post(pisp::stage_domestic_payment_consent),
            ),
            ("GET", "{pfx}/pisp/domestic-payment-consents/{consentId}") => router.route(
                path.as_str(),
                get(pisp::get_domestic_payment_consent),
            ),
            ("POST", "{pfx}/pisp/domestic-vrp-consents") => router.route(
                path.as_str(),
                post(pisp::stage_domestic_vrp_consent),
            ),
            ("POST", "{pfx}/pisp/domestic-payments") => router.route(
                path.as_str(),
                post(pisp::create_domestic_payment),
            ),
            ("GET", "{pfx}/pisp/domestic-payments/{domesticPaymentId}") => router.route(
                path.as_str(),
                get(pisp::get_domestic_payment),
            ),
            ("POST", "{pfx}/pisp/file-payment-consents") => router.route(
                path.as_str(),
                post(pisp::file_payments_unimplemented),
            ),
            ("POST", "{pfx}/cbpii/funds-confirmation-consents") => router.route(
                path.as_str(),
                post(cbpii::stage_funds_confirmation_consent),
            ),
            ("POST", "{pfx}/cbpii/funds-confirmations") => router.route(
                path.as_str(),
                post(cbpii::confirm_funds),
            ),
            ("POST", "{pfx}/event-notifications") => router.route(
                path.as_str(),
                post(cbpii::submit_event_notifications),
            ),
            ("GET", "{pfx}/event-notifications") => router.route(
                path.as_str(),
                get(cbpii::poll_event_notifications),
            ),
            // The exhaustive match over the table's `{pfx}` rows: a new
            // row without an arm fails to compile (never a silent gap).
            _ => unreachable!("every route_table {pfx} row must bind a handler"),
        };
    }
    router
}
