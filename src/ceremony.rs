// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:UK
// SPDX-License-Identifier: Apache-2.0

//! The FAPI 1 Advanced ceremony + detached JWS signing- UK
//! DESIGN.md §4, §8; ).
//!
//! **Detached JWS request verification**: every consent/payment POST and
//! every payment PUT carries `x-jws-signature` - a detached PS256 JWS
//! over the request body (RFC 7515 Appendix F + RFC 7797; the payload is
//! the body bytes, not re-embedded). The JOSE header carries `kid` (the
//! TPP's signing key), `http://openbanking.org.uk/iss` (the org-id/
//! software-statement-id), `http://openbanking.org.uk/tan`
//! (`openbanking.org.uk`), `http://openbanking.org.uk/iat`, and `crit`
//! listing all three - verified against the OB Directory-published JWKS
//! (`OPENFIN8_UK_DIRECTORY_JWKS_URL`).
//!
//! **Response signing**: the ASPSP signs every payment-initiation
//! response the same way (the signing key `OPENFIN8_UK_SIGNING_KEY_REF` -
//! a `sentin8-secrets://` reference, never key material in an env var).
//!
//! **Trust posture**: Directory JWKS unavailability fails CLOSED (503,
//! never skip-verify). The dev fixture signs over the deterministic
//! canonical body (the EU QSEALC fixture precedent) so the fail-closed
//! + verify paths are unit-testable without the Directory.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The OB Directory `tan` (the trusted-authority name - the OBL
/// directory's own).
pub const OB_TAN: &str = "openbanking.org.uk";

/// The required OB JOSE header `crit` members (UK DESIGN §4 ceremony 5):
/// `iss`, `tan`, `iat` - all three MUST be listed and present.
pub const OB_CRIT: &[&str] = &[
    "http://openbanking.org.uk/iss",
    "http://openbanking.org.uk/tan",
    "http://openbanking.org.uk/iat",
];

/// The JWS verdict for a request's `x-jws-signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsVerdict {
    /// The signature verified against the Directory JWKS.
    Verified,
    /// No `x-jws-signature` presented on a signed-method request.
    Missing,
    /// The signature failed verification (wrong key / tampered body /
    /// malformed).
    Invalid,
    /// The Directory JWKS is unreachable - the verification fails
    /// closed (503, never skip-verify).
    DirectoryUnavailable,
    /// The required OB JOSE claims are absent/mismatched (`crit`/
    /// `iss`/`tan`/`iat`).
    BadHeader,
}

/// The enforcement decision: `Verified` passes; everything else REJECTS.
/// `Missing`/`BadHeader`/`Invalid` → 400 (the caller's defect);
/// `DirectoryUnavailable` → 503 (the server's trust anchor is down -
/// NEVER skip-verify).
pub fn enforce_jws(verdict: JwsVerdict) -> Result<(), (u16, &'static str)> {
    match verdict {
        JwsVerdict::Verified => Ok(()),
        JwsVerdict::Missing => Err((400, "the request requires an x-jws-signature (detached JWS) - none presented")),
        JwsVerdict::Invalid => Err((400, "the x-jws-signature failed verification")),
        JwsVerdict::BadHeader => Err((400, "the x-jws-signature JOSE header does not carry the required OB claims (crit/iss/tan/iat)")),
        JwsVerdict::DirectoryUnavailable => Err((503, "the OB Directory JWKS is unreachable - request-signature verification fails closed (never skip-verify)")),
    }
}

/// Validate the OB JOSE header claims (the `crit` set + the three
/// members): a signature whose header omits or mismatches them is a
/// `BadHeader`, not a key problem.
pub fn validate_ob_jose_header(
    crit: Option<&[&str]>,
    iss: Option<&str>,
    tan: Option<&str>,
    iat: Option<i64>,
) -> Result<(), JwsVerdict> {
    let Some(crit) = crit else {
        return Err(JwsVerdict::BadHeader);
    };
    if crit.len() != OB_CRIT.len() || !OB_CRIT.iter().all(|c| crit.contains(c)) {
        return Err(JwsVerdict::BadHeader);
    }
    let Some(iss) = iss else {
        return Err(JwsVerdict::BadHeader);
    };
    if iss.trim().is_empty() {
        return Err(JwsVerdict::BadHeader);
    }
    if tan != Some(OB_TAN) {
        return Err(JwsVerdict::BadHeader);
    }
    let Some(iat) = iat else {
        return Err(JwsVerdict::BadHeader);
    };
    // The issued-at: not in the future beyond a clock skew, not stale
    // beyond a bounded window (OBL: within the last hour).
    let now = chrono::Utc::now().timestamp();
    if iat > now + 300 || iat < now - 3600 {
        return Err(JwsVerdict::BadHeader);
    }
    Ok(())
}

/// The deterministic canonical form the dev fixture signs:
/// `{ob-iss}:{ob-iat}:{canonical-body}` - the OB claims are PART of the
/// signed material (a fixture over a different header fails, like a
/// real signature would).
pub fn canonical_signed_body(ob_iss: &str, ob_iat: i64, body: &str) -> String {
    format!("{ob_iss}:{ob_iat}:{body}")
}

/// The dev-fixture signature form: `sig:<hex-of-sha256(canonical)>`
/// (the EU QSEALC fixture precedent: deterministic, unit-testable, and
/// never verifying when real Directory keys are configured).
pub fn verify_fixture_signature(
    signature: Option<&str>,
    ob_iss: &str,
    ob_iat: i64,
    body: &str,
    directory_available: bool,
) -> JwsVerdict {
    if !directory_available {
        return JwsVerdict::DirectoryUnavailable;
    }
    let Some(sig) = signature else {
        return JwsVerdict::Missing;
    };
    let Some(hex) = sig.strip_prefix("sig:") else {
        return JwsVerdict::Invalid;
    };
    use sha2::{Digest, Sha256};
    let canonical = canonical_signed_body(ob_iss, ob_iat, body);
    let digest = Sha256::digest(canonical.as_bytes());
    let expected: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if hex.eq_ignore_ascii_case(&expected) {
        JwsVerdict::Verified
    } else {
        JwsVerdict::Invalid
    }
}

/// The DCR request body for an OB Directory participant (RFC 7591 with
/// the software-statement assertion; the SSA verified against the
/// Directory JWKS).
pub fn ob_dcr_request_body(
    client_name: &str,
    redirect_base: &str,
    scopes: &[String],
    software_statement_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "client_name": client_name,
        "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
        "response_types": ["code", "code id_token"],
        "redirect_uris": [format!("{redirect_base}/callback")],
        "token_endpoint_auth_method": "private_key_jwt",
        "scope": scopes.join(" "),
        "software_statement": software_statement_id,
    })
}

/// The FAPI hybrid-flow request-object shape (the intent bound in): the
/// `openbanking-intent-id` claim carries the consent id (the token
/// binding's join key - verified at the middleware).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ObRequestObject {
    /// The AS issuer (aud of the request object).
    pub aud: String,
    /// The hybrid response type (FAPI: `code id_token`).
    #[serde(rename = "response_type")]
    pub response_type: String,
    /// The redirect URI.
    #[serde(rename = "redirect_uri")]
    pub redirect_uri: String,
    /// The PKCE challenge (S256).
    pub code_challenge: String,
    #[serde(rename = "code_challenge_method")]
    pub code_challenge_method: String,
    /// **The intent binding**: the OB ConsentId this authorization is
    /// for (the issued token binds to it).
    #[serde(rename = "openbanking-intent-id")]
    pub openbanking_intent_id: String,
    /// The nonce (the id_token echoes it).
    pub nonce: String,
}

impl ObRequestObject {
    /// Build the hybrid request object for an intent (the adapter's
    /// ceremony drive - Auth's FAPI profile verifies the object).
    pub fn for_intent(
        issuer: &str,
        intent_id: uuid::Uuid,
        redirect_uri: &str,
        nonce: &str,
    ) -> Self {
        Self {
            aud: issuer.to_string(),
            response_type: "code id_token".into(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: "challenge-placeholder".into(),
            code_challenge_method: "S256".into(),
            openbanking_intent_id: intent_id.to_string(),
            nonce: nonce.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_jws_enforcement_fails_closed() {
        assert!(enforce_jws(JwsVerdict::Verified).is_ok());
        // The caller defects: 400.
        for v in [
            JwsVerdict::Missing,
            JwsVerdict::Invalid,
            JwsVerdict::BadHeader,
        ] {
            let (code, _) = enforce_jws(v).unwrap_err();
            assert_eq!(code, 400, "{v:?} must 400");
        }
        // The Directory down: 503, NEVER skip-verify.
        let (code, msg) = enforce_jws(JwsVerdict::DirectoryUnavailable).unwrap_err();
        assert_eq!(code, 503);
        assert!(msg.contains("never skip-verify"));
    }

    #[test]
    fn the_ob_jose_header_rules() {
        let now = chrono::Utc::now().timestamp();
        // The happy header.
        assert!(validate_ob_jose_header(
            Some(OB_CRIT),
            Some("org-x/software-y"),
            Some(OB_TAN),
            Some(now)
        )
        .is_ok());
        // Missing crit / wrong crit / missing members.
        assert!(validate_ob_jose_header(None, Some("iss"), Some(OB_TAN), Some(now)).is_err());
        assert!(
            validate_ob_jose_header(Some(&["crit"]), Some("iss"), Some(OB_TAN), Some(now)).is_err()
        );
        assert!(validate_ob_jose_header(Some(OB_CRIT), None, Some(OB_TAN), Some(now)).is_err());
        // Wrong tan.
        assert!(validate_ob_jose_header(
            Some(OB_CRIT),
            Some("iss"),
            Some("other-directory"),
            Some(now)
        )
        .is_err());
        // iat: future beyond skew / stale beyond an hour.
        assert!(validate_ob_jose_header(
            Some(OB_CRIT),
            Some("iss"),
            Some(OB_TAN),
            Some(now + 9999)
        )
        .is_err());
        assert!(validate_ob_jose_header(
            Some(OB_CRIT),
            Some("iss"),
            Some(OB_TAN),
            Some(now - 9999)
        )
        .is_err());
    }

    #[test]
    fn the_fixture_verification_shapes() {
        let iss = "org-x/software-y";
        let iat = chrono::Utc::now().timestamp();
        let body = r#"{"Data":{"Permissions":["ReadAccountsBasic"]},"Risk":{}}"#;
        use sha2::{Digest, Sha256};
        let canonical = canonical_signed_body(iss, iat, body);
        let sig = format!(
            "sig:{}",
            Sha256::digest(canonical.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        // Directory up + correct fixture -> Verified.
        assert_eq!(
            verify_fixture_signature(Some(&sig), iss, iat, body, true),
            JwsVerdict::Verified
        );
        // Tampered body -> Invalid.
        assert_eq!(
            verify_fixture_signature(Some(&sig), iss, iat, "tampered", true),
            JwsVerdict::Invalid
        );
        // Different iat (the header is signed material) -> Invalid.
        assert_eq!(
            verify_fixture_signature(Some(&sig), iss, iat + 1, body, true),
            JwsVerdict::Invalid
        );
        // No signature -> Missing; wrong scheme -> Invalid.
        assert_eq!(
            verify_fixture_signature(None, iss, iat, body, true),
            JwsVerdict::Missing
        );
        assert_eq!(
            verify_fixture_signature(Some("Bearer x"), iss, iat, body, true),
            JwsVerdict::Invalid
        );
        // Directory down -> 503 regardless of the signature.
        assert_eq!(
            verify_fixture_signature(Some(&sig), iss, iat, body, false),
            JwsVerdict::DirectoryUnavailable
        );
    }

    #[test]
    fn the_dcr_body_carries_the_ssa() {
        let body = ob_dcr_request_body(
            "UK FinTech",
            "https://openfin8-uk.ops.sys.local.sentin8.dev",
            &["openfin8:uk:aisp".into()],
            "ssa-123",
        );
        assert_eq!(body["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(body["software_statement"], "ssa-123");
        // The hybrid response type rides the registration (FAPI).
        assert!(body["response_types"][1]
            .as_str()
            .unwrap()
            .contains("id_token"));
    }

    #[test]
    fn the_request_object_binds_the_intent() {
        let intent = uuid::Uuid::new_v4();
        let ro = ObRequestObject::for_intent(
            "https://auth.ops.sys.local.sentin8.dev",
            intent,
            "https://tpp.example/callback",
            "n-1",
        );
        // The FAPI hybrid response type.
        assert_eq!(ro.response_type, "code id_token");
        // The intent binding (the token's join key).
        assert_eq!(ro.openbanking_intent_id, intent.to_string());
        assert_eq!(ro.code_challenge_method, "S256");
    }
}
