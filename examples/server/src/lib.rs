//! Axum demo server library for dpop-auth.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{
        HeaderMap, HeaderName, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dpop_auth::{
    AuthService, DpopConfig, DpopError, DpopLayer, DpopSession, DpopState, LoginOutcome,
    ServiceError,
    dpop::{ValidationContext, validate_dpop_proof},
    service::RegisterParams,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AppState {
    pub dpop: DpopState,
    pub auth_service: Arc<AuthService>,
}

#[derive(Clone, Deserialize)]
pub struct RegisterRequest {
    pub kind: String,
    pub value: String,
    pub password: String,
    #[serde(default = "default_name")]
    pub name: String,
}

#[derive(Clone, Deserialize)]
pub struct LoginRequest {
    pub kind: String,
    pub value: String,
    pub password: String,
}

fn default_name() -> String {
    "User".to_string()
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub fn service_error_response(e: ServiceError) -> Response {
    let status = match e {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Conflict(_) => StatusCode::CONFLICT,
        ServiceError::RegistrationDisabled => StatusCode::FORBIDDEN,
        ServiceError::Validation(_) => StatusCode::BAD_REQUEST,
        ServiceError::Internal(_) | _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (status, Json(serde_json::json!({"error": e.to_string()}))).into_response()
}

pub async fn register(
    State(app): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let proof = match headers.get("DPoP") {
        Some(p) => match p.to_str() {
            Ok(s) => s,
            Err(_) => return DpopError::InvalidSignature("bad DPoP header".into()).into_response(),
        },
        None => return DpopError::MissingHeader.into_response(),
    };

    let htu = format!(
        "{}{}",
        app.dpop.config.public_url.trim_end_matches('/'),
        uri.path()
    );

    let validated = match validate_dpop_proof(ValidationContext {
        proof,
        expected_htm: "POST",
        expected_htu: &htu,
        access_token: None,
        nonce_required: app.dpop.config.nonce_required,
        clock_skew: app.dpop.config.clock_skew,
        allowed_algs: &app.dpop.config.allowed_algs,
        jti_cache: &app.dpop.jti_cache,
        nonce_cache: &app.dpop.nonce_cache,
    })
    .await
    {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);

    let params = RegisterParams {
        kind: &body.kind,
        value: &body.value,
        password: &body.password,
        name: &body.name,
        jkt: &validated.jwk_thumbprint,
        client_ip: addr.ip(),
        user_agent,
    };

    match app.auth_service.register(params).await {
        Ok(tokens) => (
            StatusCode::CREATED,
            Json(TokenResponse {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                token_type: tokens.token_type.to_string(),
                expires_in: tokens.expires_in,
            }),
        )
            .into_response(),
        Err(e) => service_error_response(e),
    }
}

pub async fn login(
    State(app): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(body): Json<LoginRequest>,
) -> Response {
    let proof = match headers.get("DPoP") {
        Some(p) => match p.to_str() {
            Ok(s) => s,
            Err(_) => return DpopError::InvalidSignature("bad DPoP header".into()).into_response(),
        },
        None => return DpopError::MissingHeader.into_response(),
    };

    let htu = format!(
        "{}{}",
        app.dpop.config.public_url.trim_end_matches('/'),
        uri.path()
    );

    let validated = match validate_dpop_proof(ValidationContext {
        proof,
        expected_htm: "POST",
        expected_htu: &htu,
        access_token: None,
        nonce_required: app.dpop.config.nonce_required,
        clock_skew: app.dpop.config.clock_skew,
        allowed_algs: &app.dpop.config.allowed_algs,
        jti_cache: &app.dpop.jti_cache,
        nonce_cache: &app.dpop.nonce_cache,
    })
    .await
    .map_err(|e| e.into_response())
    {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let jkt = validated.jwk_thumbprint;

    match app
        .auth_service
        .login(
            &body.kind,
            &body.value,
            &body.password,
            &jkt,
            "0.0.0.0".parse().unwrap(),
            None,
        )
        .await
    {
        Ok(LoginOutcome::Success { tokens }) => Json(TokenResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: tokens.token_type.to_string(),
            expires_in: tokens.expires_in,
        })
        .into_response(),

        Ok(LoginOutcome::Requires2fa) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "2FA required"})),
        )
            .into_response(),

        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "unsupported login outcome"})),
        )
            .into_response(),

        Err(e) => service_error_response(e),
    }
}

pub async fn me(session: DpopSession) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "sub": session.sub,
        "jkt": session.jkt
    }))
}

pub async fn create_app(config: DpopConfig, pool: sqlx::PgPool) -> Router {
    let state = DpopState::new(config.clone());
    let auth_service = Arc::new(AuthService::new(pool.clone(), config));
    let app_state = AppState {
        dpop: state.clone(),
        auth_service,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([CONTENT_TYPE, AUTHORIZATION, HeaderName::from_static("dpop")])
        .expose_headers([HeaderName::from_static("dpop-nonce")]);

    Router::new()
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/api/me", get(me).layer(DpopLayer::new(state)))
        .layer(cors)
        .with_state(app_state)
}
