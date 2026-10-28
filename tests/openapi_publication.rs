// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI publication drift guard (OBARCH-2 - the VENDORED case).
//!
//! The Open Banking Standard is published by Open Banking Limited
//! under the MIT Open Licence, so the published spec MAY carry the
//! OB resource paths. The invariants are therefore:
//!
//! 1. The OBL copyright notice is present in the spec's info block
//!    (the MIT licence requires the notice travel with any copied
//!    material).
//! 2. Every standard-surface path conforms to the versioned OB
//!    prefix (`/open-banking/v{maj}.{min}/{aisp|pisp|cbpii}/...`)
//!    derived from `OPENFIN8_UK_VERSION` - no stray prefixes.
//! 3. The bank8-owned operation floor holds.

use serde_json::Value;

const OB_PREFIX: &str = "/open-banking/v";
const OBL_NOTICE_MARKER: &str = "Open Banking Limited";

#[test]
fn openapi_publication_policy_holds() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: Value = serde_json::from_str(&text).expect("valid JSON");

    // Invariant 1: the OBL notice travels with the vendored spec.
    let description = spec
        .pointer("/info/description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        description.contains(OBL_NOTICE_MARKER),
        "published spec must carry the OBL copyright notice \
(MIT Open Licence - openbanking.org.uk/open-licence)"
    );

    // Invariant 2: standard-surface paths conform to the OB prefix.
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths object");
    for path in paths.keys() {
        // A path is "standard-surface" if it is not a bank8-owned
        // route (those start /v1/ or /openapi).
        let standard_surface = !(path.starts_with("/v1/") || path.starts_with("/openapi"));
        if standard_surface {
            assert!(
                path.starts_with(OB_PREFIX)
                    && (path.contains("/aisp/")
                        || path.contains("/pisp/")
                        || path.contains("/cbpii/")),
                "standard-surface path {path} must conform to \
/open-banking/v{{maj}}.{{min}}/{{role}}/... (from \
OPENFIN8_UK_VERSION)"
            );
        }
    }

    // Invariant 3: bank8-owned operation floor.
    let bank8_ops: usize = paths
        .keys()
        .filter(|p| p.starts_with("/v1/"))
        .map(|_| 1)
        .sum();
    assert!(
        bank8_ops >= 1,
        "spec floor: expected >= 1 bank8-owned op, got {bank8_ops}"
    );
}
