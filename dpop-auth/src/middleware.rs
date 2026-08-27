//! The DPoP middleware: a `tower::Layer` that authenticates every request.

use std::{convert::Infallible, pin::Pin};

use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use http::{HeaderName, Request, header};
use tower::Service;

use crate::{
    DpopError,
    dpop::{ValidationContext, validate_dpop_proof},
    extractor::ValidatedSession,
    state::DpopState,
    token::verify_access_token,
};

/// A `tower::Layer` that validates DPoP proofs and success tokens.
#[derive(Clone)]
pub struct DpopLayer {
    state: DpopState,
}

impl DpopLayer {
    /// Create the layer from a [`DpopState`].
    pub fn new(state: DpopState) -> Self {
        Self { state }
    }
}

impl<S> tower::Layer<S> for DpopLayer {
    type Service = DpopService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DpopService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Canonical name of the `DPoP` request header.
///
/// Header names are case-insensitive (RFC 9110), and `http` normalizes the to lowercase.
/// The constant avoids re-parsing the name on every request.
static DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");

/// Extract exactly one `Dpop` header value.
fn exactly_one_dpop_header(req: &Request<Body>) -> Result<&str, DpopError> {
    let mut values = req.headers().get_all(&DPOP_HEADER).iter();

    let first = values.next().ok_or(DpopError::MissingHeader)?;

    if values.next().is_some() {
        return Err(DpopError::InvalidSignature(
            "multiple DPoP headers present".into(),
        ));
    }

    first
        .to_str()
        .map_err(|_| DpopError::InvalidSignature("invalid DPoP header encoding".into()))
}

/// Extract the authorization token, proof, method and path from a request.
fn extract(req: &Request<Body>) -> Result<(String, String, String, String), DpopError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("DPoP "))
        .map(str::to_owned)
        .ok_or(DpopError::MissingHeader)?;

    let proof = exactly_one_dpop_header(req)?.to_owned();
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();

    Ok((token, proof, method, path))
}

fn build_htu(public_url: &str, path: &str) -> String {
    format!("{}{}", public_url.trim_end_matches('/'), path)
}

async fn authenticate(
    state: &DpopState,
    token: String,
    proof: String,
    method: String,
    path: String,
) -> Result<ValidatedSession, DpopError> {
    let config = &state.config;

    let claims = verify_access_token(
        config.signer.algorithm(),
        config.signer.decoding_key(),
        &token,
        &config.issuer,
        &config.audience,
        config.clock_skew,
    )?;

    let htu = build_htu(&config.public_url, &path);

    let validated = validate_dpop_proof(ValidationContext {
        proof: &proof,
        expected_htm: &method,
        expected_htu: &htu,
        access_token: Some(&token),
        nonce_required: config.nonce_required,
        clock_skew: config.clock_skew,
        allowed_algs: &config.allowed_algs,
        jti_cache: &state.jti_cache,
        nonce_cache: &state.nonce_cache,
    })
    .await?;

    if claims.cnf.jkt != validated.jwk_thumbprint {
        return Err(DpopError::InvalidSignature("jkt mismatch".into()));
    }

    Ok(ValidatedSession {
        sub: claims.sub,
        jti: claims.jti,
        jkt: claims.cnf.jkt,
        extra: claims.extra,
    })
}

/// The service produced by [`DpopLayer`].
#[derive(Clone)]
pub struct DpopService<S> {
    inner: S,
    state: DpopState,
}
impl<S> Service<Request<Body>> for DpopService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        // Extract headers synchronously (no borrows survive into the async block).
        let extracted = extract(&req);

        Box::pin(async move {
            let (token, proof, method, path) = match extracted {
                Ok(parts) => parts,
                Err(err) => return Ok(err.into_response()),
            };

            match authenticate(&state, token, proof, method, path).await {
                Ok(session) => {
                    req.extensions_mut().insert(session);

                    inner.call(req).await
                }
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{Router, routing::get};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use http::{StatusCode, header::AUTHORIZATION};
    use jsonwebtoken::{
        EncodingKey, Header, encode,
        jwk::{
            AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType,
            Jwk,
        },
    };
    use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
    use tower::ServiceExt;

    use crate::{
        DpopConfig, DpopSession, TokenSigner,
        crypto::{compute_ath, compute_jwk_thumbprint},
        token::{AccessTokenClaims, Confirmation, issue_access_token},
    };

    use super::*;

    const PUBLIC_URL: &str = "https://example.com";

    struct TestClient {
        secret: SecretKey,
        jwk: Jwk,
        thumbprint: String,
    }

    impl TestClient {
        fn new() -> Self {
            let secret = SecretKey::generate();
            let signing_key = SigningKey::from(&secret);
            let verifying_key = signing_key.verifying_key();
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

            let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();

            Self {
                secret,
                jwk,
                thumbprint,
            }
        }

        fn proof(
            &self,
            htm: &str,
            htu: &str,
            access_token: Option<&str>,
            nonce: Option<&str>,
        ) -> String {
            let mut map = serde_json::Map::new();
            map.insert("htm".to_string(), serde_json::json!(htm));
            map.insert("htu".to_string(), serde_json::json!(htu));
            map.insert(
                "iat".to_string(),
                serde_json::json!(jsonwebtoken::get_current_timestamp()),
            );
            map.insert(
                "jti".to_string(),
                serde_json::json!(uuid::Uuid::new_v4().to_string()),
            );

            if let Some(n) = nonce {
                map.insert("nonce".to_string(), serde_json::json!(n));
            };

            if let Some(token) = access_token {
                map.insert("ath".to_string(), serde_json::json!(compute_ath(token)));
            };

            let claims = serde_json::Value::Object(map);

            let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
            header.typ = Some("dpop+jwt".to_string());
            header.jwk = Some(self.jwk.clone());

            let der = self.secret.to_pkcs8_der().unwrap();
            let key = EncodingKey::from_ec_der(der.as_bytes());

            encode(&header, &claims, &key).unwrap()
        }
    }

    fn config(nonce_required: bool) -> DpopConfig {
        DpopConfig::builder()
            .public_url(PUBLIC_URL)
            .issuer(PUBLIC_URL)
            .audience(PUBLIC_URL)
            .signer(TokenSigner::symmetric(b"test-secret"))
            .nonce_required(nonce_required)
            .build()
            .unwrap()
    }

    async fn handler(session: DpopSession) -> String {
        session.sub
    }

    fn router(nonce_required: bool) -> Router {
        let state = DpopState::new(config(nonce_required));
        Router::new()
            .route("/resource", get(handler))
            .layer(DpopLayer::new(state.clone()))
            .with_state(state)
    }

    fn issue(jkt: &str, sub: &str, extra: serde_json::Map<String, serde_json::Value>) -> String {
        let config = config(false);
        issue_access_token(
            &config.signer,
            &config.issuer,
            &config.audience,
            Duration::from_secs(900),
            sub,
            jkt,
            extra,
        )
        .unwrap()
    }

    fn request(token: &str, proof: &str) -> Request<Body> {
        axum::http::Request::builder()
            .method("GET")
            .uri("/resource")
            .header(AUTHORIZATION, format!("DPoP {}", token))
            .header("DPoP", proof)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn valid_request_accepted() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let response = router(false)
            .oneshot(request(&token, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_authorization_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let req = Request::builder()
            .method("GET")
            .uri("/resource")
            .header("DPoP", proof)
            .body(Body::empty())
            .unwrap();

        let response = router(false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(www_auth, r#"DPoP error="invalid_dpop_proof""#);
    }

    #[tokio::test]
    async fn missing_proof_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());

        let req = Request::builder()
            .method("GET")
            .uri("/resource")
            .header(AUTHORIZATION, format!("DPoP {token}"))
            .body(Body::empty())
            .unwrap();

        let response = router(false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn htm_mismatch_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("POST", "https://example.com/resource", Some(&token), None);

        let response = router(false)
            .oneshot(request(&token, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn htu_mismatch_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/other", Some(&token), None);

        let response = router(false)
            .oneshot(request(&token, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ath_mismatch_rejected() {
        let client = TestClient::new();
        let token1 = issue(&client.thumbprint, "user-1", Default::default());
        let token2 = issue(&client.thumbprint, "user-2", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token1), None);

        let response = router(false)
            .oneshot(request(&token2, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jkt_mismatch_rejected() {
        let client1 = TestClient::new();
        let client2 = TestClient::new();
        let token = issue(&client1.thumbprint, "user-1", Default::default());
        let proof = client2.proof("GET", "https://example.com/resource", Some(&token), None);

        let response = router(false)
            .oneshot(request(&token, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jti_replay_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let r = router(false);

        let r1 = r.clone().oneshot(request(&token, &proof)).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = r.oneshot(request(&token, &proof)).await.unwrap();
        assert_eq!(r2.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dpop_header_is_case_insensitive() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let req = Request::builder()
            .method("GET")
            .uri("/resource")
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", proof)
            .body(Body::empty())
            .unwrap();

        let response = router(false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn multiple_dpop_header_rejected() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let req = Request::builder()
            .method("GET")
            .uri("/resource")
            .header(AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", &proof)
            .header("DPoP", &proof)
            .body(Body::empty())
            .unwrap();

        let response = router(false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let client = TestClient::new();
        let config = config(false);
        let now = jsonwebtoken::get_current_timestamp();

        let claims = AccessTokenClaims {
            sub: "user-1".into(),
            iss: PUBLIC_URL.into(),
            aud: PUBLIC_URL.into(),
            exp: now - 3600,
            iat: now - 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            cnf: Confirmation {
                jkt: client.thumbprint.clone(),
            },
            extra: Default::default(),
        };
        let header = Header::new(config.signer.algorithm());
        let token = encode(&header, &claims, config.signer.encoding_key()).unwrap();
        let proof = client.proof("GET", "https://example.com/resource", Some(&token), None);

        let response = router(false)
            .oneshot(request(&token, &proof))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nonce_flow_requires_nonce() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());

        let r = router(true);
        let proof_without_nonce =
            client.proof("GET", "https://example.com/resource", Some(&token), None);
        let r1 = r
            .clone()
            .oneshot(request(&token, &proof_without_nonce))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);

        let nonce = r1
            .headers()
            .get("DPoP-Nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let proof_with_nonce = client.proof(
            "GET",
            "https://example.com/resource",
            Some(&token),
            Some(&nonce),
        );
        let r2 = r.oneshot(request(&token, &proof_with_nonce)).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn nonce_required_returns_proper_challenge() {
        let client = TestClient::new();
        let token = issue(&client.thumbprint, "user-1", Default::default());
        let proof_without_nonce =
            client.proof("GET", "https://example.com/resource", Some(&token), None);

        let response = router(true)
            .oneshot(request(&token, &proof_without_nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let www_auth = response
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(www_auth, r#"DPoP error="use_dpop_nonce""#);
        assert!(response.headers().contains_key("DPoP-Nonce"));
    }

    #[tokio::test]
    async fn jkt_mismatch_returns_exact_error_kind() {
        let state = DpopState::new(config(false));
        let client1 = TestClient::new();
        let client2 = TestClient::new();

        let token = issue(&client1.thumbprint, "user-1", Default::default());
        let proof = client2.proof("GET", "https://example.com/resource", Some(&token), None);

        let result = authenticate(&state, token, proof, "GET".into(), "/resource".into()).await;

        assert!(matches!(result, Err(DpopError::InvalidSignature(msg)) if msg == "jkt mismatch"),)
    }

    #[tokio::test]
    async fn missing_header_returns_exact_error_kind() {
        let req = Request::builder()
            .method("GET")
            .uri("/resource")
            .body(Body::empty())
            .unwrap();

        let result = extract(&req);

        assert!(matches!(result, Err(DpopError::MissingHeader)));
    }

    #[derive(Debug, serde::Deserialize)]
    struct AppClaims {
        role: String,
    }
    crate::impl_from_extra!(AppClaims);

    async fn claims_handler(session: DpopSession<AppClaims>) -> String {
        session.claims.role
    }

    #[tokio::test]
    async fn custom_claims_extracted() {
        let state = DpopState::new(config(false));
        let r = Router::new()
            .route("/claims", get(claims_handler))
            .layer(DpopLayer::new(state.clone()))
            .with_state(state);

        let client = TestClient::new();
        let extra = serde_json::json!({"role": "admin"})
            .as_object()
            .unwrap()
            .clone();
        let token = issue(&client.thumbprint, "user-1", extra);
        let proof = client.proof("GET", "https://example.com/claims", Some(&token), None);

        let req = Request::builder()
            .method("GET")
            .uri("/claims")
            .header(AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::empty())
            .unwrap();

        let response = r.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
