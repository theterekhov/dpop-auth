//! DPoP proof validation (RFC 9449, section 4.3).

use std::time::Duration;

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
    pub jwk_thumbprint: String,
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
    /// Allowed clock skew for the `iat` freshness window.
    pub clock_skew: Duration,
    /// JWS algorithms accepted for the proof.
    pub allowed_algs: &'a [Algorithm],
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
        clock_skew,
        allowed_algs,
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

    if !allowed_algs.contains(&header.alg) {
        tracing::debug!("rejecting DPoP proof: alg {:?} not allowed", header.alg);

        return Err(DpopError::InvalidAlgorithm(format!(
            "{:?} now allowed",
            header.alg
        )));
    }

    let jwk = header
        .jwk
        .ok_or_else(|| DpopError::InvalidSignature("jwk missing in header".into()))?;

    let jwk_thumbprint = jwk
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
    let window = clock_skew.as_secs();
    let in_window =
        claims.iat.saturating_sub(window) <= now && now <= claims.iat.saturating_add(window);
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
        let Some(provided_ath) = claims.ath.as_deref() else {
            return Err(DpopError::InvalidSignature(
                "missing ath claim in resource proof".into(),
            ));
        };

        let computed = compute_ath(token);
        if !bool::from(provided_ath.as_bytes().ct_eq(computed.as_bytes())) {
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
        jwk_thumbprint,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use jsonwebtoken::{
        EncodingKey, Header, encode,
        jwk::{
            AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType,
        },
    };
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
    use tokio::task::JoinSet;

    use crate::cache::{create_jti_cache, create_nonce_cache};

    use super::*;

    struct TestClient {
        secret: SecretKey,
        jwk: Jwk,
    }

    impl TestClient {
        fn new() -> Self {
            let secret = SecretKey::generate();
            let singing_key = SigningKey::from(&secret);
            let verifying_key = singing_key.verifying_key();
            let point = verifying_key.to_sec1_point(false);

            let jwk = Jwk {
                common: Default::default(),
                algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                    key_type: EllipticCurveKeyType::EC,
                    curve: EllipticCurve::P256,
                    x: Base64UrlUnpadded::encode_string(point.x().unwrap()),
                    y: Base64UrlUnpadded::encode_string(point.y().unwrap()),
                }),
            };

            Self { secret, jwk }
        }

        fn sign(&self, header: &Header, claims: &DpopClaims) -> String {
            let der = self.secret.to_pkcs8_der().unwrap();
            let key = EncodingKey::from_ec_der(der.as_bytes());

            encode(header, claims, &key).unwrap()
        }

        fn default_header(&self) -> Header {
            let mut header = Header::new(Algorithm::ES256);
            header.typ = Some("dpop+jwt".to_string());
            header.jwk = Some(self.jwk.clone());
            header
        }

        fn default_claims(
            &self,
            htm: &str,
            htu: &str,
            nonce: Option<&str>,
            access_token: Option<&str>,
            iat: Option<u64>,
        ) -> DpopClaims {
            DpopClaims {
                htm: htm.to_string(),
                htu: htu.to_string(),
                iat: iat.unwrap_or_else(jsonwebtoken::get_current_timestamp),
                jti: Uuid::new_v4().to_string(),
                nonce: nonce.map(str::to_string),
                ath: access_token.map(compute_ath),
            }
        }

        fn proof(
            &self,
            htm: &str,
            htu: &str,
            nonce: Option<&str>,
            access_token: Option<&str>,
            iat: Option<u64>,
        ) -> String {
            self.sign(
                &self.default_header(),
                &self.default_claims(htm, htu, nonce, access_token, iat),
            )
        }
    }

    /// Build a raw JWT from explicit header/payload JSON with a dummy signature.
    ///
    /// Used for rejections that happen before signature verification
    /// (typ, alg, jwk), where a real signature would be pointless.
    fn manual_proof(header: &str, payload: &str) -> String {
        let h = Base64UrlUnpadded::encode_string(header.as_bytes());
        let p = Base64UrlUnpadded::encode_string(payload.as_bytes());
        let s = Base64UrlUnpadded::encode_string(b"dummy");

        format!("{}.{}.{}", h, p, s)
    }

    // cache

    #[tokio::test]
    async fn jti_cache_insert_and_contains() {
        let cache = create_jti_cache();
        cache.insert("test-jti".into(), true).await;
        assert!(cache.contains_key("test-jti"));
    }

    #[tokio::test]
    async fn nonce_cache_insert_and_contains() {
        let cache = create_nonce_cache();
        cache.insert("test-nonce".into(), true).await;
        assert!(cache.contains_key("test-nonce"));
    }

    #[tokio::test]
    async fn entry_or_insert_is_atomic_concurrent() {
        let cache = Arc::new(create_jti_cache());
        let jti = "concurrent-test-jti".to_string();
        let mut set = JoinSet::new();

        for _ in 0..100 {
            let c = cache.clone();
            let j = jti.clone();

            set.spawn(async move { c.entry(j).or_insert(true).await.is_fresh() });
        }

        let mut fresh = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                fresh += 1;
            }
        }

        assert_eq!(fresh, 1, "ровно одна вставка должна быть fresh");
    }

    // normalize_htu

    #[test]
    fn normalize_htu_drops_default_port() {
        assert_eq!(
            normalize_htu("https://example.com:443/path").unwrap(),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_htu("https://example.com/path").unwrap(),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_htu_lowercases_host() {
        assert_eq!(
            normalize_htu("https://EXAMPLE.COM/path").unwrap(),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_htu_keeps_non_default_port() {
        assert_eq!(
            normalize_htu("https://example.com:8443/path").unwrap(),
            "https://example.com:8443/path"
        );
    }

    #[test]
    fn normalize_htu_invalid_url_errors() {
        assert!(normalize_htu("not a url").is_err());
    }

    // validation

    const TEST_ALGS: &[Algorithm] = &[Algorithm::ES256, Algorithm::PS256];
    const TEST_SKEW: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn valid_proof_is_accepted() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof("POST", "https://example.com/login", None, None, None);

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await
        .unwrap();

        assert_eq!(result.jwk_thumbprint.len(), 43);
        assert_eq!(result.claims.htm, "POST");
    }

    #[tokio::test]
    async fn proof_too_large_rejected() {
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let giant = "x".repeat(9000);

        let result = validate_dpop_proof(ValidationContext {
            proof: &giant,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn invalid_typ_rejected() {
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = manual_proof(r#"{"typ":"bearer","alg":"ES256"}"#, "{}");

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::InvalidTyp(_))));
    }

    #[tokio::test]
    async fn invalid_alg_rejected() {
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = manual_proof(r#"{"typ":"dpop+jwt","alg":"HS256"}"#, "{}");

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::InvalidAlgorithm(_))));
    }

    #[tokio::test]
    async fn missing_jwk_rejected() {
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = manual_proof(r#"{"typ":"dpop+jwt","alg":"ES256"}"#, "{}");

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn htm_mismatch_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof("POST", "https://example.com/login", None, None, None);

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "GET",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::HtmMismatch { .. })));
    }

    #[tokio::test]
    async fn htu_mismatch_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof("POST", "https://example.com/login", None, None, None);

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/other",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::HtuMismatch)));
    }

    #[tokio::test]
    async fn ath_mismatch_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof(
            "POST",
            "https://example.com/login",
            None,
            Some("token-a"),
            None,
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: Some("token-b"),
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::InvalidSignature(_))));
    }

    #[tokio::test]
    async fn ath_matches_accepted() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof(
            "POST",
            "https://example.com/resource",
            None,
            Some("token"),
            None,
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/resource",
            access_token: Some("token"),
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn jti_replay_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof("POST", "https://example.com/login", None, None, None);

        let ctx = || ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        };

        assert!(validate_dpop_proof(ctx()).await.is_ok());
        assert!(matches!(
            validate_dpop_proof(ctx()).await,
            Err(DpopError::JtiReplay)
        ));
    }

    #[tokio::test]
    async fn iat_in_past_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let now = jsonwebtoken::get_current_timestamp();
        let proof = client.proof(
            "POST",
            "https://example.com/login",
            None,
            None,
            Some(now - 120),
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[tokio::test]
    async fn iat_in_future_rejected() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let now = jsonwebtoken::get_current_timestamp();
        let proof = client.proof(
            "POST",
            "https://example.com/login",
            None,
            None,
            Some(now + 120),
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: false,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::Expired)));
    }

    #[tokio::test]
    async fn nonce_required_token_endpoint() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof("POST", "https://example.com/login", None, None, None);

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: true,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::TokenNonceRequired(_))));
    }

    #[tokio::test]
    async fn nonce_required_resource() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();
        let proof = client.proof(
            "POST",
            "https://example.com/login",
            None,
            Some("token"),
            None,
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: Some("token"),
            nonce_required: true,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(matches!(result, Err(DpopError::ResourceNonceRequired(_))));
    }

    #[tokio::test]
    async fn nonce_valid_accepted() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();

        nonce_cache.insert("known-nonce".into(), true).await;
        let proof = client.proof(
            "POST",
            "https://example.com/login",
            Some("known-nonce"),
            None,
            None,
        );

        let result = validate_dpop_proof(ValidationContext {
            proof: &proof,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: true,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn nonce_can_be_reused_across_requests() {
        let client = TestClient::new();
        let jti_cache = create_jti_cache();
        let nonce_cache = create_nonce_cache();

        nonce_cache.insert("reusable-nonce".into(), true).await;

        let proof1 = client.proof(
            "POST",
            "https://example.com/login",
            Some("reusable-nonce"),
            None,
            None,
        );
        let proof2 = client.proof(
            "POST",
            "https://example.com/login",
            Some("reusable-nonce"),
            None,
            None,
        );

        let result1 = validate_dpop_proof(ValidationContext {
            proof: &proof1,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: true,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        let result2 = validate_dpop_proof(ValidationContext {
            proof: &proof2,
            expected_htm: "POST",
            expected_htu: "https://example.com/login",
            access_token: None,
            nonce_required: true,
            jti_cache: &jti_cache,
            nonce_cache: &nonce_cache,
            allowed_algs: TEST_ALGS,
            clock_skew: TEST_SKEW,
        })
        .await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }
}
