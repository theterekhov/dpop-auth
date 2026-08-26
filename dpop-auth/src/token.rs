//! Access-token issue and verification with `cnf.jkt` confirmation.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode, errors::ErrorKind};
use serde::{Deserialize, Serialize};

use crate::{DpopError, config::TokenSigner};

/// RFC 7800 confirmation: the `jkt` JWK thumbprint of the bound key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmation {
    /// JWK SHA-256 thumbprint of the public key
    /// the token is bound to.
    pub jkt: String,
}

/// The claims of an issued access token.
///
/// The first set of fields is required; `extra` carries application-specific claims
/// (`email`, `role`, `tenant_id`, ...) through `#[serde(flatten)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject identifier (the authenticated user).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiry, Unix seconds.
    pub exp: u64,
    /// Issued-at, Unix seconds.
    pub iat: u64,
    /// Unique token identifier.
    pub jti: String,
    /// Key confirmation (`cnf.jkt`).
    pub cnf: Confirmation,
    /// Application-specific claims.
    ///
    /// Reserved keys (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `cnf`)
    /// are owned by the library: a value for one of them here is ignored,
    /// the named field wins.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Issue a DPoP-bound access token.
///
/// The caller controls `sub` (subject) and `jkt` (key confirmation).
/// The reserved claims (`iss`, `aud`, `exp`, `iat`, `jti`, `cnf`)
/// are filled by this function and must not be overridden vie `extra`.
///
/// # NOTE
///
/// Expiry calculating note:
/// Uses `saturating_add` to prevent overflow panics in debug mode
/// or integer wrapping in release mode when very large TTL values
/// (e.g., `Duration::MAX`) are configured.
pub fn issue_access_token(
    signer: &TokenSigner,
    issuer: &str,
    audience: &str,
    ttl: Duration,
    subject: &str,
    jkt: &str,
    extra: serde_json::Map<String, serde_json::Value>,
) -> Result<String, DpopError> {
    let now = jsonwebtoken::get_current_timestamp();

    let claims = AccessTokenClaims {
        sub: subject.to_string(),
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: now.saturating_add(ttl.as_secs()),
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        cnf: Confirmation {
            jkt: jkt.to_string(),
        },
        extra,
    };

    let header = Header::new(signer.algorithm());

    encode(&header, &claims, signer.encoding_key()).map_err(|e| DpopError::Internal(e.to_string()))
}

/// Verify a DPoP-bound access token and return its claims.
///
/// `clock_skew` is used as leeway for the `exp` check
/// to tolerate clock drift between the issuer and the verifier.
/// Expired tokens are reported as [`DpopError::Expired`],
/// everything else as [`DpopError::InvalidSignature`].
pub fn verify_access_token(
    algorithm: Algorithm,
    decoding_key: &DecodingKey,
    token: &str,
    issuer: &str,
    audience: &str,
    clock_skew: Duration,
) -> Result<AccessTokenClaims, DpopError> {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.leeway = clock_skew.as_secs();
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);

    decode::<AccessTokenClaims>(token, decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => DpopError::Expired,
            _ => DpopError::InvalidSignature(e.to_string()),
        })
}

#[cfg(test)]
mod tests {

    use base64ct::{Base64UrlUnpadded, Encoding};
    use jsonwebtoken::EncodingKey;
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};

    use super::*;

    const ISSUER: &str = "https://auth.example.com";
    const AUDIENCE: &str = "api";
    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const CLOCK_SKEW: Duration = Duration::from_secs(60);

    fn symmetric() -> TokenSigner {
        TokenSigner::symmetric(b"test-secret")
    }

    fn asymmetric() -> TokenSigner {
        let secret = SecretKey::generate();
        let signing_key = SigningKey::from(&secret);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_sec1_point(false);

        let private_der = secret.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ec_der(private_der.as_bytes());

        let x = Base64UrlUnpadded::encode_string(point.x().unwrap());
        let y = Base64UrlUnpadded::encode_string(point.y().unwrap());
        let decoding_key = DecodingKey::from_ec_components(&x, &y).unwrap();

        TokenSigner::asymmetric(encoding_key, decoding_key)
    }

    fn extra() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({"role": "customer", "tenant_id": "t-1"})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn hs256_issue_verify_roundtrip() {
        let signer = symmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            Default::default(),
        )
        .unwrap();

        let claims = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        )
        .unwrap();

        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.cnf.jkt, JKT);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.aud, AUDIENCE);
    }

    #[test]
    fn es256_issue_verify_roundtrip() {
        let signer = asymmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            Default::default(),
        )
        .unwrap();

        let claims = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        )
        .unwrap();

        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.cnf.jkt, JKT);
    }

    #[test]
    fn extra_claims_preserved() {
        let signer = symmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            extra(),
        )
        .unwrap();

        let claims = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        )
        .unwrap();

        assert_eq!(claims.extra["role"], serde_json::json!("customer"));
        assert_eq!(claims.extra["tenant_id"], serde_json::json!("t-1"));
    }

    #[test]
    fn tampered_token_rejected() {
        let signer = symmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            Default::default(),
        )
        .unwrap();

        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();

        let result = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &tampered,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        );
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let signer = symmetric();
        let now = jsonwebtoken::get_current_timestamp();

        let claims = AccessTokenClaims {
            sub: "user-1".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: now - 3600,
            iat: now - 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            cnf: Confirmation { jkt: JKT.into() },
            extra: Default::default(),
        };

        let header = Header::new(signer.algorithm());
        let token = encode(&header, &claims, signer.encoding_key()).unwrap();

        let result = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let signer = symmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            Default::default(),
        )
        .unwrap();

        let result = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            "https://evil.com",
            AUDIENCE,
            CLOCK_SKEW,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_audience_rejected() {
        let signer = symmetric();
        let token = issue_access_token(
            &signer,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(900),
            "user-1",
            JKT,
            Default::default(),
        )
        .unwrap();

        let result = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            "other-api",
            CLOCK_SKEW,
        );
        assert!(result.is_err());
    }

    #[test]
    fn expired_maps_to_expired_variant() {
        let signer = symmetric();
        let now = jsonwebtoken::get_current_timestamp();

        let claims = AccessTokenClaims {
            sub: "user-1".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: now - 3600,
            iat: now - 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            cnf: Confirmation { jkt: JKT.into() },
            extra: Default::default(),
        };
        let header = Header::new(signer.algorithm());
        let token = encode(&header, &claims, signer.encoding_key()).unwrap();

        let result = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            CLOCK_SKEW,
        );

        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[test]
    fn token_within_leeway_accepted() {
        let signer = symmetric();
        let now = jsonwebtoken::get_current_timestamp();

        let claims = AccessTokenClaims {
            sub: "user-1".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: now - 59,
            iat: now - 59,
            jti: uuid::Uuid::new_v4().to_string(),
            cnf: Confirmation { jkt: JKT.into() },
            extra: Default::default(),
        };

        let header = Header::new(signer.algorithm());
        let token = encode(&header, &claims, signer.encoding_key()).unwrap();

        let ok = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(60),
        );
        assert!(ok.is_ok(), "token within leeway must be accepted");

        let strict = verify_access_token(
            signer.algorithm(),
            signer.decoding_key(),
            &token,
            ISSUER,
            AUDIENCE,
            Duration::ZERO,
        );
        assert!(
            matches!(strict, Err(DpopError::Expired)),
            "without leeway is must be expired"
        );
    }
}
