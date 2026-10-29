// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 OpenFin8:UK - UK open banking: the Open Banking Limited
//! (OBL) Read/Write API ASPSP surface (v3.1.x, v4.0.1 configurable),
//! serving AISPs, PISPs, and CBPIIs over
//! `/open-banking/v{maj}.{min}/{aisp|pisp|cbpii}/*`. See
//! `DESIGN.md` (OBARCH-5).
//!
//! This service embeds `openfin8-core` (the jurisdiction-agnostic
//! kernel - OBARCH-1) and supplies the UK OBIE profile, the FAPI 1
//! Advanced ceremony (client_credentials intent staging, hybrid flow
//! with request objects, detached JWS signing), and the OB resource
//! router with the `{Data, Links, Meta}` envelope codec.
//!
//! Skeleton - the OBARCH-1 core extraction lands first; this binary
//! then takes the OB wire handlers, the intent-based consent model
//! over core's `awaiting_authorization` state, and its registration
//! data. Auth gains the FAPI 1 Advanced profile flag alongside
//! (sequenced with this adapter).
//!
//! Spec publication (OBARCH-2) is the VENDORED case: the Open Banking
//! Standard is published under the MIT Open Licence, so the published
//! `docs/openapi.json` MAY carry the OB resource paths WITH the OBL
//! copyright notice preserved (see `src/openapi.rs`).

use utoipa::OpenApi;

use openfin8_uk_server::{openapi, registration, router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("openfin8:uk", "OPENFIN8_UK")
            .with_registration(registration::print)
            .with_own_health()
            .with_state(router::build_state)
            .with_router(router::routes)
            .with_openapi(openapi::UkOpenApi::openapi()),
    )
    .await
}
