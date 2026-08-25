//! DPoP proof validation (RFC 9449, section 4.3).

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    errors::ErrorKind,
    jwk::{Jwk, ThumbprintHash},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use crate::{
    DpopError,
    cache::{JtiCache, NonceCache},
    crypto::compute_ath,
};

/// Maximum accepted size of a DPoP proof, in bytes (RFC 9449, section 11.1).
const MAX_PROOF_LEN: usize = 8192;
/// Freshness
const IAT_WINDOW_SECS: u64 = 60;

/// The claims carried by a DPoP proof JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    /// HTTP method the proof is bound to (`htm`).
    pub htm: String,
    /// HTTP target URI the proof is bound to (`htu`), without query/fragment.
    pub htu: String,
    /// Creation time (`iat`), checked against the freshness window.
    pub iat: u64,
    /// Unique proof identifier (`jti`), used for replay protection.
    pub jti: String,
    /// Optional server-provided nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Optional access-token hash (`ath`), present only for resource requests.
    #[serde(default)]
    pub ath: Option<String>,
}

/// A successfully validated DPoP proof.
pub struct ValidatedProof {
    /// The public key from the proof header.
    pub jwk: Jwk,
    /// The validated claims.
    pub claims: DpopClaims,
    /// The JWK thumbprint, used as the `cnf.jkt` value in access tokens.
    pub jwk_tbumbprint: String,
}

/// Everything needed to validate a DPoP proof for one request.
pub struct ValidationContext<'a> {
    /// The proof JWT taken from the `DPoP` header.
    pub proof: &'a str,
    /// The expected HTTP method (`htm`).
    pub expected_htm: &'a str,
    /// The expected HTTP target URI (`htu`), normalized against the request.
    pub expected_htu: &'a str,
    /// The access token, if the request targets a protected resource.
    ///
    /// When `Some`, the proof must carry a matching `ath`. When `None`
    /// (token endpoint), no `ath` is required.
    pub access_token: Option<&'a str>,
    /// Whether the server requires a valid nonce is the proof.
    pub nonce_required: bool,
    /// Cache of already-seen `jti` values.
    pub jti_cache: &'a JtiCache,
    /// Cache of nonces issued by this server.
    pub nonce_cache: &'a NonceCache,
}

/// Validate a DPoP proof against RFC 9449, section 4.3.
///
/// The checks run in a deliberate order: cheap structural checks first, the
/// expensive signature verification before any cache mutation, and the `jti`
/// replay check last (only fully valid proofs consume a cache slot).
pub async fn validate_dpop_proof(ctx: ValidationContext<'_>) -> Result<ValidatedProof, DpopError> {
    let ValidationContext {
        proof,
        expected_htm,
        expected_htu,
        access_token,
        nonce_required,
        jti_cache,
        nonce_cache,
    } = ctx;

    if proof.len() > MAX_PROOF_LEN {
        tracing::debug!("rejecting DPoP proof: exceeds {} bytes", MAX_PROOF_LEN);

        return Err(DpopError::InvalidSignature(
            "proof too large (max 8KB)".into(),
        ));
    }

    let header = decode_header(proof).map_err(|e| DpopError::InvalidSignature(e.to_string()))?;

    if header.typ.as_deref() != Some("dpop+jwt") {
        tracing::debug!("rejecting DPoP proof: typ is not dpop+jwt");

        return Err(DpopError::InvalidTyp(header.typ.unwrap_or_default()));
    }

    if header.alg != Algorithm::ES256 && header.alg != Algorithm::PS256 {
        tracing::debug!("rejecting DPoP proof: alg {:?} not allowed", header.alg);

        return Err(DpopError::InvalidAlgorithm(format!(
            "{:?} not allowed (use ES256 or PS256)",
            header.alg
        )));
    }

    let jwk = header
        .jwk
        .ok_or_else(|| DpopError::InvalidSignature("jwk missing in header".into()))?;

    let jwk_tbumbprint = jwk
        .thumbprint(ThumbprintHash::SHA256)
        .map_err(|_| DpopError::InvalidSignature("failed to compute JWK thumbprint".into()))?;

    let key =
        DecodingKey::from_jwk(&jwk).map_err(|e| DpopError::InvalidSignature(e.to_string()))?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let claims = decode::<DpopClaims>(proof, &key, &validation)
        .map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => DpopError::Expired,
            _ => DpopError::InvalidSignature(e.to_string()),
        })?
        .claims;

    let now = jsonwebtoken::get_current_timestamp();
    let in_window = claims.iat.saturating_sub(IAT_WINDOW_SECS) <= now
        && now <= claims.iat.saturating_add(IAT_WINDOW_SECS);
    if !in_window {
        tracing::debug!("rejecting DPoP proof: iat {} outside window", claims.iat);

        return Err(DpopError::Expired);
    }

    if !claims.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::HtmMismatch {
            expected: expected_htm.to_string(),
            got: claims.htm,
        });
    }

    if normalize_htu(&claims.htu)? != normalize_htu(expected_htu)? {
        return Err(DpopError::HtuMismatch);
    }

    if nonce_required && !nonce_cache.contains_key(claims.nonce.as_deref().unwrap_or_default()) {
        let new_nonce = Uuid::new_v4().to_string();
        nonce_cache.insert(new_nonce.clone(), true).await;

        return Err(if access_token.is_some() {
            DpopError::ResourceNonceRequired(new_nonce)
        } else {
            DpopError::TokenNonceRequired(new_nonce)
        });
    }

    if let Some(token) = access_token {
        let computed = compute_ath(token);
        let matches = claims
            .ath
            .as_deref()
            .is_some_and(|provided| bool::from(provided.as_bytes().ct_eq(computed.as_bytes())));

        if !matches {
            return Err(DpopError::InvalidSignature("ath mismatch".into()));
        }
    }

    let entry = jti_cache.entry(claims.jti.clone()).or_insert(true).await;
    if !entry.is_fresh() {
        tracing::debug!("rejecting DPoP proof: jti {} already seen", claims.jti);

        return Err(DpopError::JtiReplay);
    }

    Ok(ValidatedProof {
        jwk,
        claims,
        jwk_tbumbprint,
    })
}

fn normalize_htu(raw: &str) -> Result<String, DpopError> {
    let url = Url::parse(raw).map_err(|_| DpopError::HtuMismatch)?;

    let mut normalized = String::new();
    normalized.push_str(url.scheme());
    normalized.push_str("://");

    if let Some(host) = url.host_str() {
        normalized.push_str(host);
    }

    if let Some(port) = url.port() {
        normalized.push(':');
        normalized.push_str(&port.to_string());
    }

    normalized.push_str(url.path());

    Ok(normalized)
}
