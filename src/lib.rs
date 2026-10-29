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
//! see DESIGN.md (OBARCH-5).

pub mod aisp;
pub mod cbpii;
pub mod ceremony;
pub mod consent;
pub mod envelope;
pub mod openapi;
pub mod pisp;
pub mod registration;
pub mod router;
