// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! Library target for the openfin8-uk service (the integration tests
//! and the e2e harness link against this; the binary is `src/main.rs`).
//! The intent consent model lives in `consent.rs`; the FAPI/JWS
//! machinery in `ceremony.rs`; the OB envelope + error model in
//! `envelope.rs`; the aisp/pisp/cbpii surfaces in their modules; the
//! routes in `router.rs`; the registration data in `registration.rs` -
//! see DESIGN.md).

pub mod aisp;
pub mod cbpii;
pub mod ceremony;
pub mod consent;
pub mod envelope;
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::UkOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

pub mod pisp;
pub mod registration;
pub mod router;
