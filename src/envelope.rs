// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The OB envelope codec + the OBL error semantics (OBARCH-5 - UK
//! DESIGN.md §5; backlog UK-4).
//!
//! **The envelope** (`{Data, Risk, Links, Meta}`): responses wrap the
//! handler's document in the OB envelope with absolute `Links.Self` +
//! pagination links (`Meta.TotalPages`); requests unwrap `Data`/`Risk`
//! before the handler sees them.
//!
//! **The conditional-field semantics**: conditional fields are EXCLUDED
//! (never empty-string/zero) and `0..*` arrays are present-but-empty -
//! both enforced in the codec (pure, fixture-tested).
//!
//! **The error model**: `OBErrorResponse1`
//! (`{Errors: [{ErrorCode, Message, Path, Url}]}` with the OB
//! error-code vocabulary `UK.OBIE.Field.Missing` etc.) and the OBL
//! rules - unknown resource id → `400`, defined-but-unimplemented →
//! `404`, empty list → `200`-with-empty-array.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── The envelope ───────────────────────────────────────────────────────

/// The OB response envelope: `{Data, Risk, Links, Meta}` (OBL R/W Data
/// API Profile).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObEnvelope<T> {
    /// The resource document.
    pub data: T,
    /// The risk payload (present-but-empty when the resource carries
    /// none - the `0..*` rule).
    pub risk: serde_json::Value,
    /// The absolute self-link + the pagination links.
    pub links: ObLinks,
    /// The pagination meta.
    pub meta: ObMeta,
}

/// The OB `Links` member (absolute URLs; `Self` mandatory, `Next`/
/// `Prev` present only when the page has a neighbor - the
/// conditional-field rule).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObLinks {
    /// The absolute URL of this response.
    pub self_url: String,
    /// The next page (absent on the last page - conditional exclusion).
    #[serde(rename = "Next", skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// The previous page (absent on the first page).
    #[serde(rename = "Prev", skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

/// The OB `Meta` member.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObMeta {
    /// The total pages (the pagination meta; `1` for single documents).
    #[serde(rename = "TotalPages")]
    pub total_pages: i64,
    /// The first available transaction datetime (AIS lists only -
    /// absent otherwise: the conditional rule).
    #[serde(
        rename = "FirstAvailableDateTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_available_date_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(
        rename = "LastAvailableDateTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_available_date_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// The OB request body's unwrapped form: the handler sees `Data`/`Risk`
/// only (the codec strips the envelope).
#[derive(Debug, Clone, Deserialize)]
pub struct ObRequestBody {
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub risk: serde_json::Value,
}

/// Unwrap an OB request body (the codec's request half): accepts BOTH
/// the enveloped form (`{Data: {...}, Risk: {...}}`) and the bare
/// document (the dev-direct form) - the handler always receives the
/// `Data` document.
pub fn unwrap_request(body: &serde_json::Value) -> serde_json::Value {
    if let Some(data) = body.get("Data") {
        return data.clone();
    }
    body.clone()
}

/// Wrap a handler document into the OB envelope (the codec's response
/// half): the self-link absolute, the pagination links conditional.
pub fn wrap_response(
    data: serde_json::Value,
    self_url: &str,
    total_pages: i64,
    page: Option<(i64, i64)>, // (current, total) for the Next/Prev links
) -> serde_json::Value {
    let (next, prev) = match page {
        Some((current, total)) => {
            let next = if current < total {
                Some(format!("{self_url}?page={}", current + 1))
            } else {
                None
            };
            let prev = if current > 1 {
                Some(format!("{self_url}?page={}", current - 1))
            } else {
                None
            };
            (next, prev)
        }
        None => (None, None),
    };
    serde_json::json!({
        "Data": data,
        "Risk": {},
        "Links": { "Self": self_url, "Next": next, "Prev": prev },
        "Meta": { "TotalPages": total_pages },
    })
}

/// The OB conditional-field exclusion rule (OBL): a `null` field is
/// EXCLUDED from the serialized document (never rendered as
/// empty-string/zero/null); an empty ARRAY stays present-but-empty.
/// Applied recursively over the whole document.
pub fn exclude_conditionals(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if v.is_null() {
                    continue; // conditional exclusion: absent, not null
                }
                out.insert(k.clone(), exclude_conditionals(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            // The `0..*` rule: present-but-empty arrays stay.
            serde_json::Value::Array(items.iter().map(exclude_conditionals).collect())
        }
        other => other.clone(),
    }
}

// ── The error model ────────────────────────────────────────────────────

/// One OB error (`OBErrorResponse1.Errors[*]`).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObErrorItem {
    /// The OB error code (the `UK.OBIE.*` vocabulary).
    #[serde(rename = "ErrorCode")]
    pub error_code: String,
    /// The human message.
    #[serde(rename = "Message")]
    pub message: String,
    /// The field path (present when the error is field-scoped -
    /// the conditional rule).
    #[serde(rename = "Path", skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The URL of the schema element that failed.
    #[serde(rename = "Url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// The `OBErrorResponse1` shape - the adapter's error renderer.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ObErrorResponse {
    /// The HTTP status code as a string (the OB ErrorResponse shape).
    #[serde(rename = "Code")]
    pub code: String,
    /// A unique id for this error response.
    #[serde(rename = "Id")]
    pub id: Option<String>,
    /// The human message.
    #[serde(rename = "Message")]
    pub message: String,
    /// The errors array (at least one item).
    #[serde(rename = "Errors")]
    pub errors: Vec<ObErrorItem>,
}

// The OB error-code vocabulary (OBL R/W Data API Profile - the subset
// this adapter emits; each carries the `UK.OBIE.` prefix).
pub const OB_ERR_FIELD_MISSING: &str = "UK.OBIE.Field.Missing";
pub const OB_ERR_FIELD_INVALID: &str = "UK.OBIE.Field.InvalidDate";
pub const OB_ERR_RESOURCE_UNKNOWN: &str = "UK.OBIE.Resource.NotFound";
pub const OB_ERR_RESOURCE_NOT_IMPLEMENTED: &str = "UK.OBIE.Resource.NotImplemented";
pub const OB_ERR_UNSUPPORTED_CONSENT_STATUS: &str =
    "UK.OBIE.Unsupported.ConsentStatusOrConsentType";
pub const OB_ERR_SIGNATURE_INVALID: &str = "UK.OBIE.Signature.Invalid";
pub const OB_ERR_SIGNATURE_MISSING: &str = "UK.OBIE.Signature.Missing";
pub const OB_ERR_DIRECTORY_UNAVAILABLE: &str = "UK.OBIE.Directory.Unavailable";
pub const OB_ERR_IDEMPOTENCY: &str = "UK.OBIE.IdempotencyError";
pub const OB_ERR_FORBIDDEN: &str = "UK.OBIE.Forbidden";

impl ObErrorResponse {
    /// Build the OBL 400-for-unknown-resource-id error (the OBL rule:
    /// NEVER a bare 404 for a typed id).
    pub fn unknown_resource_id(id: &str) -> Self {
        Self {
            code: "400".into(),
            id: Some(uuid::Uuid::new_v4().to_string()),
            message: format!("unknown resource id {id} - the OBL rule: 400"),
            errors: vec![ObErrorItem {
                error_code: OB_ERR_RESOURCE_UNKNOWN.into(),
                message: format!("unknown resource id {id}"),
                path: None,
                url: None,
            }],
        }
    }

    /// Build the 404-for-defined-but-unimplemented error.
    pub fn not_implemented(resource: &str) -> Self {
        Self {
            code: "404".into(),
            id: Some(uuid::Uuid::new_v4().to_string()),
            message: format!(
                "the {resource} resource is defined but not implemented by this deployment"
            ),
            errors: vec![ObErrorItem {
                error_code: OB_ERR_RESOURCE_NOT_IMPLEMENTED.into(),
                message: format!("the {resource} resource is not implemented"),
                path: None,
                url: None,
            }],
        }
    }

    /// Build the signature errors (missing/invalid/directory).
    pub fn signature(kind: &str) -> Self {
        let (code, msg) = match kind {
            "missing" => (OB_ERR_SIGNATURE_MISSING, "no x-jws-signature presented"),
            "invalid" => (
                OB_ERR_SIGNATURE_INVALID,
                "the x-jws-signature failed verification",
            ),
            _ => (
                OB_ERR_DIRECTORY_UNAVAILABLE,
                "the OB Directory is unavailable - verification fails closed",
            ),
        };
        Self {
            code: if kind == "directory" {
                "503".into()
            } else {
                "400".into()
            },
            id: Some(uuid::Uuid::new_v4().to_string()),
            message: msg.into(),
            errors: vec![ObErrorItem {
                error_code: code.into(),
                message: msg.into(),
                path: None,
                url: None,
            }],
        }
    }

    /// Build the consent-status error (the chokepoint's verdict).
    pub fn unsupported_consent_status(msg: &str) -> Self {
        Self {
            code: "400".into(),
            id: Some(uuid::Uuid::new_v4().to_string()),
            message: msg.into(),
            errors: vec![ObErrorItem {
                error_code: OB_ERR_UNSUPPORTED_CONSENT_STATUS.into(),
                message: msg.into(),
                path: None,
                url: None,
            }],
        }
    }

    /// Build a generic field error.
    pub fn field(error_code: &str, message: &str, path: Option<String>) -> Self {
        Self {
            code: "400".into(),
            id: Some(uuid::Uuid::new_v4().to_string()),
            message: message.into(),
            errors: vec![ObErrorItem {
                error_code: error_code.into(),
                message: message.into(),
                path,
                url: None,
            }],
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_wraps_with_absolute_self_link() {
        let data = serde_json::json!({"ConsentId": "c-1"});
        let env = wrap_response(
            data.clone(),
            "https://bank.example/open-banking/v3.1/aisp/consents/c-1",
            1,
            None,
        );
        assert_eq!(env["Data"], data);
        assert_eq!(env["Risk"], serde_json::json!({}));
        assert_eq!(
            env["Links"]["Self"],
            "https://bank.example/open-banking/v3.1/aisp/consents/c-1"
        );
        assert_eq!(env["Meta"]["TotalPages"], 1);
        // No pagination context -> no Next/Prev (the conditional rule).
        assert!(env["Links"]["Next"].is_null());
        assert!(env["Links"]["Prev"].is_null());
    }

    #[test]
    fn the_pagination_links_are_conditional() {
        // Page 1 of 3: Next present, Prev absent.
        let env = wrap_response(
            serde_json::json!([1]),
            "https://bank.example/accounts",
            3,
            Some((1, 3)),
        );
        assert_eq!(env["Links"]["Next"], "https://bank.example/accounts?page=2");
        assert!(env["Links"]["Prev"].is_null());
        // Page 3 of 3: Prev present, Next absent.
        let env = wrap_response(
            serde_json::json!([3]),
            "https://bank.example/accounts",
            3,
            Some((3, 3)),
        );
        assert_eq!(env["Links"]["Prev"], "https://bank.example/accounts?page=2");
        assert!(env["Links"]["Next"].is_null());
        // Page 2 of 3: both.
        let env = wrap_response(
            serde_json::json!([2]),
            "https://bank.example/accounts",
            3,
            Some((2, 3)),
        );
        assert!(env["Links"]["Next"].is_string());
        assert!(env["Links"]["Prev"].is_string());
    }

    #[test]
    fn the_request_unwrap_strips_the_envelope() {
        // The enveloped form -> the Data document.
        let enveloped = serde_json::json!({
            "Data": {"Permissions": ["ReadAccountsBasic"]},
            "Risk": {},
        });
        assert_eq!(
            unwrap_request(&enveloped),
            serde_json::json!({"Permissions": ["ReadAccountsBasic"]})
        );
        // The bare form passes through.
        let bare = serde_json::json!({"Permissions": ["ReadAccountsBasic"]});
        assert_eq!(unwrap_request(&bare), bare);
    }

    #[test]
    fn the_conditional_exclusion_rule() {
        let doc = serde_json::json!({
            "always": "present",
            "conditional": null,
            "empty_array": [],
            "nested": {"also_null": null, "kept": 1},
            "zero": 0,
        });
        let out = exclude_conditionals(&doc);
        // The null field is EXCLUDED (never rendered as null).
        assert!(out.get("conditional").is_none());
        // The empty array stays present-but-empty (the 0..* rule).
        assert_eq!(out["empty_array"], serde_json::json!([]));
        // Recursive exclusion.
        assert!(out["nested"].get("also_null").is_none());
        assert_eq!(out["nested"]["kept"], 1);
        // A real zero is data, not a conditional miss - kept.
        assert_eq!(out["zero"], 0);
        assert_eq!(out["always"], "present");
    }

    #[test]
    fn the_obl_error_rules() {
        // Unknown resource id -> 400 (NEVER a bare 404 for a typed id).
        let e = ObErrorResponse::unknown_resource_id("c-unknown");
        assert_eq!(e.code, "400");
        assert_eq!(e.errors[0].error_code, OB_ERR_RESOURCE_UNKNOWN);
        // Defined-but-unimplemented -> 404.
        let e = ObErrorResponse::not_implemented("file-payments");
        assert_eq!(e.code, "404");
        assert_eq!(e.errors[0].error_code, OB_ERR_RESOURCE_NOT_IMPLEMENTED);
        // The signature errors.
        assert_eq!(ObErrorResponse::signature("missing").code, "400");
        assert_eq!(ObErrorResponse::signature("invalid").code, "400");
        assert_eq!(ObErrorResponse::signature("directory").code, "503");
        // The consent-status verdict error.
        let e = ObErrorResponse::unsupported_consent_status("the consent was revoked");
        assert_eq!(e.errors[0].error_code, OB_ERR_UNSUPPORTED_CONSENT_STATUS);
        // The field error carries the OB code vocabulary.
        let e = ObErrorResponse::field(
            OB_ERR_FIELD_MISSING,
            "Permissions is required",
            Some("Data.Permissions".into()),
        );
        assert_eq!(e.errors[0].path.as_deref(), Some("Data.Permissions"));
    }
}
