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
