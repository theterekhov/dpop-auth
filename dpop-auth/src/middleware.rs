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
