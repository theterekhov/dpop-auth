//! End-to-end DPoP flow: register -> login -> protected resource.

use std::net::SocketAddr;

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::Request,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dpop_auth::{
    DpopConfig, Jwk, TokenSigner,
    crypto::{compute_ath, compute_jwk_thumbprint},
};
use jsonwebtoken::{
    EncodingKey, Header, encode,
    jwk::{AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType},
};
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
use sqlx::PgPool;
use tower::ServiceExt;

const PUBLIC_URL: &str = "http://localhost:3000";
const TEST_SIGNER_SECRET: &[u8; 32] = b"secret-key-32-bytes-long-1234567";

struct Client {
    secret: SecretKey,
    jwk: Jwk,
}

impl Client {
    fn new() -> Self {
        let secret = SecretKey::generate();
        let signing = SigningKey::from(&secret);
        let point = signing.verifying_key().to_sec1_point(false);

        let jwk = Jwk {
            common: Default::default(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: Base64UrlUnpadded::encode_string(point.x().expect("x coordinate missing")),
                y: Base64UrlUnpadded::encode_string(point.y().expect("y coordinate missing")),
            }),
        };

        Self { secret, jwk }
    }

    fn proof(&self, htm: &str, htu: &str, ath: Option<&str>) -> String {
        let mut map = serde_json::Map::new();
        map.insert("htm".into(), serde_json::json!(htm));
        map.insert("htu".into(), serde_json::json!(htu));
        map.insert(
            "iat".into(),
            serde_json::json!(jsonwebtoken::get_current_timestamp()),
        );
        map.insert(
            "jti".into(),
            serde_json::json!(uuid::Uuid::new_v4().to_string()),
        );
        if let Some(token) = ath {
            map.insert("ath".into(), serde_json::json!(compute_ath(token)));
        }

        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(self.jwk.clone());

        let der = self
            .secret
            .to_pkcs8_der()
            .expect("failed to export PKCS#8 DER");
        let key = EncodingKey::from_ec_der(der.as_bytes());

        encode(&header, &serde_json::Value::Object(map), &key).expect("failed to encode DPoP JWT")
    }
}

#[sqlx::test]
async fn full_dpop_flow_register_login_then_me(pool: PgPool) {
    dpop_auth::store::run_migrations(&pool)
        .await
        .expect("failed to run migrations.");

    let config = DpopConfig::builder()
        .public_url(PUBLIC_URL)
        .allow_registration(true)
        .signer(TokenSigner::symmetric(TEST_SIGNER_SECRET).unwrap())
        .build()
        .expect("failed to build DpopConfig");

    let client = Client::new();
    let jkt = compute_jwk_thumbprint(&client.jwk).expect("failed to compute thumbprint");
    let app = server::create_app(config, pool).await;
    let addr = "0.0.0.0:12345".parse::<SocketAddr>().unwrap();

    // 1. /api/auth/register
    let reg_proof = client.proof("POST", "http://localhost:3000/api/auth/register", None);
    let reg_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("DPoP", reg_proof)
                .header("Content-Type", "application/json")
                .extension(ConnectInfo(addr))
                .body(Body::from(
                    r#"
                 	{
                  		"name": "John",
                    	"kind": "email",
                     	"value": "john@example.com",
                      	"password": "password123"
                  	}
                 	"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(reg_resp.status(), 201, "register must returns 201 Created");
    let reg_body = to_bytes(reg_resp.into_body(), 4096).await.unwrap();
    let reg_json = serde_json::from_slice::<serde_json::Value>(&reg_body).unwrap();
    assert!(
        reg_json.get("access_token").is_some(),
        "register must issue initial access_token"
    );

    // 2. /api/auth/login
    let login_proof = client.proof("POST", "http://localhost:3000/api/auth/login", None);
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("DPoP", login_proof)
                .header("Content-Type", "application/json")
                .extension(ConnectInfo(addr))
                .body(Body::from(
                    r#"
                 	{
                  		"kind": "email",
                    	"value": "john@example.com",
                     	"password": "password123"
                  	}
                 	"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_resp.status(), 200, "login must returns 200 OK");
    let login_body = to_bytes(login_resp.into_body(), 4096).await.unwrap();
    let login_json = serde_json::from_slice::<serde_json::Value>(&login_body).unwrap();
    let access_token = login_json["access_token"]
        .as_str()
        .expect("missing access_token on login response")
        .to_string();

    // 3. /api/me
    let me_proof = client.proof("GET", "http://localhost:3000/api/me", Some(&access_token));
    let me_resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/me")
                .header("DPoP", me_proof)
                .header("Authorization", format!("DPoP {access_token}"))
                .extension(ConnectInfo(addr))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        me_resp.status(),
        200,
        "/me must succeed with a valid DPoP proof"
    );
    let me_body = to_bytes(me_resp.into_body(), 4096).await.unwrap();
    let me_json = serde_json::from_slice::<serde_json::Value>(&me_body).unwrap();
    assert_eq!(
        me_json["jkt"], jkt,
        "returned jkt must match client key thumbprint"
    );
}
