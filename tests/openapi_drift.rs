// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI coverage drift guard (OAPEC - the router↔spec equality; the
//! EU adapter's `route_table()` precedent).
//!
//! Both directions: every SERVED route must be spec'd AND every spec'd
//! path must be served. The UK route table is prefix-templated
//! (`{pfx}` renders the deployment's versioned OB prefix); the spec
//! carries the concrete `/open-banking/v3.1` paths (the default
//! version) - the guard renders the table with the same default prefix
//! before comparing (a version change regenerates the spec; the table
//! never changes).

use serde_json::Value;
use std::collections::BTreeSet;

/// The (method, path) pairs the router serves (the concrete-prefix
/// render of `route_table()`).
fn served_pairs() -> BTreeSet<(String, String)> {
    openfin8_uk_server::router::route_table()
        .iter()
        .map(|(m, p)| (m.to_string(), p.replace("{pfx}", "/open-banking/v3.1")))
        .collect()
}

/// The (method, path) pairs the published spec documents.
fn spec_pairs() -> BTreeSet<(String, String)> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: Value = serde_json::from_str(&text).expect("valid JSON");
    let mut pairs = BTreeSet::new();
    let paths = spec
        .pointer("/paths")
        .and_then(Value::as_object)
        .expect("paths object");
    for (path, ops) in paths {
        for (method, op) in ops.as_object().into_iter().flatten() {
            if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete")
                && op.is_object()
            {
                pairs.insert((method.to_uppercase(), path.clone()));
            }
        }
    }
    pairs
}

#[test]
fn spec_covers_every_served_route_and_vice_versa() {
    let served = served_pairs();
    let spec = spec_pairs();
    let missing: Vec<_> = served.difference(&spec).collect();
    let stale: Vec<_> = spec.difference(&served).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "router↔spec drift - served-not-spec'd: {missing:?}; spec'd-not-served: {stale:?}"
    );
    // The floor: the OB surface's operation count (the consent resources
    // + the aisp reads + the pisp submissions + cbpii + the events).
    assert!(
        spec.len() >= 16,
        "spec floor: expected >= 16 ops for the landed OB surface, got {}",
        spec.len()
    );
}
