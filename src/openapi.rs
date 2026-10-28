// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:OpenUK
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Bank8:OpenUK.
//!
//! OBARCH-2 - the VENDORED case: the Open Banking Standard is
//! published by Open Banking Limited under the MIT Open Licence
//! (openbanking.org.uk/open-licence), so this adapter MAY carry the
//! OB resource paths in its published spec **with the OBL copyright
//! notice preserved**. The utoipa aggregate below therefore grows
//! to include the OB resource annotations as the wire lands
//! (OBARCH-5), and the OBL notice travels in the spec's info block.
//!
//! The drift guard (`tests/openapi_publication.rs`) asserts the
//! notice is present and that OB paths conform to the versioned
//! prefix (`/open-banking/v{maj}.{min}/...`) - the inverse of the
//! US/CA policy.

use utoipa::OpenApi;

/// The OBL MIT Open Licence notice that MUST accompany any copied
/// Open Banking Standard material (spec paths derived from the R/W
/// API). Rendered into the published spec's info block - wired into
/// the utoipa description when the OB paths land (OBARCH-5); the
/// drift guard tests against the marker string.
#[allow(dead_code)]
pub const OBL_OPEN_LICENCE_NOTICE: &str = "The Open Banking Standard \
is subject to the Open Banking Limited MIT Open Licence \
(https://www.openbanking.org.uk/open-licence). Copyright Open \
Banking Limited.";

/// Bank8:OpenUK OpenAPI surface: bank8-owned routes plus (as the
/// wire lands) the OB resource paths under the OBL notice.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "bank8-open-uk",
        description = "Sentin8 Bank8:OpenUK - UK open banking (OBL \
Read/Write API v3.1.x/v4.0.1). The Open Banking Standard is \
published by Open Banking Limited under the MIT Open Licence \
(https://www.openbanking.org.uk/open-licence); portions of the \
Read/Write API surface included here are used under that licence \
with the OBL copyright notice preserved.",
        license(name = "MIT OR Apache-2.0", identifier = "MIT OR Apache-2.0"),
        version = "0.1.0"
    ),
    paths(),
    components(schemas()),
    security()
)]
pub struct UkOpenApi;
