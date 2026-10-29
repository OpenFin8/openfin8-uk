// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for OpenFin8:UK.
//!
//! The VENDORED case: the Open Banking Standard is
//! published by Open Banking Limited under the MIT Open Licence
//! (openbanking.org.uk/open-licence), so this adapter MAY carry the
//! OB resource paths in its published spec **with the OBL copyright
//! notice preserved**. The utoipa aggregate carries the OB resource
//! annotations, and the OBL notice travels in the spec's info block.
//!
//! The drift guard (`tests/openapi_publication.rs`) asserts the
//! notice is present and that OB paths conform to the versioned
//! prefix (`/open-banking/v{maj}.{min}/...`) - the inverse of the
//! US/CA policy.

use utoipa::OpenApi;

/// The OBL MIT Open Licence notice that MUST accompany any copied
/// Open Banking Standard material (spec paths derived from the R/W
/// API). Rendered into the published spec's info block - wired into
/// the utoipa description when the OB paths land); the
/// drift guard tests against the marker string.
#[allow(dead_code)]
pub const OBL_OPEN_LICENCE_NOTICE: &str = "The Open Banking Standard \
is subject to the Open Banking Limited MIT Open Licence \
(https://www.openbanking.org.uk/open-licence). Copyright Open \
Banking Limited.";

/// OpenFin8:UK OpenAPI surface: OpenFin8-owned routes plus (as the
/// wire lands) the OB resource paths under the OBL notice.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "openfin8-uk",
        description = "Sentin8 OpenFin8:UK - UK open banking (OBL \
Read/Write API v3.1.x/v4.0.1). The Open Banking Standard is \
published by Open Banking Limited under the MIT Open Licence \
(https://www.openbanking.org.uk/open-licence); portions of the \
Read/Write API surface included here are used under that licence \
with the OBL copyright notice preserved.",
        license(name = "MIT OR Apache-2.0", identifier = "MIT OR Apache-2.0"),
        version = "0.1.0"
    ),
    paths(
        crate::consent::stage_aisp_consent,
        crate::consent::get_aisp_consent,
        crate::consent::delete_aisp_consent,
        crate::consent::sweep_staged_intents,
        crate::aisp::get_accounts,
        crate::aisp::get_account_subresource,
        crate::aisp::download_statement,
        crate::pisp::stage_domestic_payment_consent,
        crate::pisp::get_domestic_payment_consent,
        crate::pisp::stage_domestic_vrp_consent,
        crate::pisp::create_domestic_payment,
        crate::pisp::get_domestic_payment,
        crate::pisp::file_payments_unimplemented,
        crate::cbpii::stage_funds_confirmation_consent,
        crate::cbpii::confirm_funds,
        crate::cbpii::submit_event_notifications,
        crate::cbpii::poll_event_notifications,
    ),
    components(schemas(
        crate::consent::StageConsentRequest,
        crate::consent::ConsentResponse,
        crate::ceremony::ObRequestObject,
        crate::envelope::ObErrorItem,
        crate::envelope::ObErrorResponse,
        crate::pisp::DomesticPaymentConsentRequest,
        crate::pisp::DomesticVrpConsentRequest,
        crate::pisp::VrpControlParameters,
        crate::pisp::DomesticPaymentRequest,
        crate::pisp::PaymentResult,
        crate::cbpii::FundsConfirmationConsentRequest,
        crate::cbpii::FundsConfirmationRequest,
        crate::cbpii::FundsConfirmationResponse,
        crate::cbpii::FundsAvailable,
        crate::cbpii::EventNotificationSubmission,
        crate::cbpii::EventNotificationResponse,
    )),
    security()
)]
pub struct UkOpenApi;
