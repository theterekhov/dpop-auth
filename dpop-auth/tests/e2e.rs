//! Vertical-slice E2E: mock WebCrypto -> proof -> token -> RLS isolation.

#![cfg(feature = "postgres")]

use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use dpop_auth::{
    DpopConfig, Jwk, TenantTx, TokenSigner,
    cache::{jti::create_jti_cache, nonce::create_nonce_cache},
    crypto::{compute_ath, compute_jwk_thumbprint},
    dpop::{ValidationContext, validate_dpop_proof},
    token::issue_access_token,
};
use jsonwebtoken::{
    EncodingKey, Header, encode,
    jwk::{AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType},
};
use p256::{SecretKey, ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
use sqlx::PgPool;
use uuid::Uuid;

const PUBLIC_URL: &str = "https://example.com";

/// The "browser" side: an EC key and its public JWK. In the real demo this
/// is WebCrypto (non-extractable); here `p256` stands in as the mock.
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
                x: Base64UrlUnpadded::encode_string(point.x().unwrap()),
                y: Base64UrlUnpadded::encode_string(point.y().unwrap()),
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
        map.insert("jti".into(), serde_json::json!(Uuid::new_v4().to_string()));

        if let Some(token) = ath {
            map.insert("ath".into(), serde_json::json!(compute_ath(token)));
        }

        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(self.jwk.clone());

        let der = self.secret.to_pkcs8_der().unwrap();
        let key = EncodingKey::from_ec_der(der.as_bytes());

        encode(&header, &serde_json::Value::Object(map), &key).unwrap()
    }
}

async fn setup_rls(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let (tenant_a, tenant_b) = (Uuid::new_v4(), Uuid::new_v4());

    sqlx::query(
        r#"
     	DROP TABLE IF EXISTS demo_tickets
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	DROP TABLE IF EXISTS demo_tenants
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
     	CREATE TABLE demo_tenants (
      		id UUID PRIMARY KEY,
        	name TEXT NOT NULL
      	)
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	CREATE TABLE demo_tickets (
      		id UUID PRIMARY KEY,
        	tenant_id UUID NOT NULL REFERENCES demo_tenants(id),
         	title TEXT NOT NULL
      	)
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
     	INSERT INTO demo_tenants (id, name)
      	VALUES ($1, 'A'), ($2, 'B')
     	"#,
    )
    .bind(tenant_a)
    .bind(tenant_b)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	INSERT INTO demo_tickets (id, tenant_id, title)
      	VALUES ($1, $2, 'A ticket')
     	"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_a)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	INSERT INTO demo_tickets (id, tenant_id, title)
      	VALUES ($1, $2, 'B ticket')
     	"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_b)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
     	DO $$ BEGIN
      		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dpop_app')
        		THEN CREATE ROLE dpop_app;
          	END IF;
      	END $$
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	GRANT SELECT, INSERT, UPDATE, DELETE ON demo_tenants, demo_tickets TO dpop_app
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
     	ALTER TABLE demo_tickets ENABLE ROW LEVEL SECURITY
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	ALTER TABLE demo_tickets FORCE ROW LEVEL SECURITY
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	DROP POLICY IF EXISTS tenant_isolation ON demo_tickets
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
     	CREATE POLICY tenant_isolation ON demo_tickets
      		USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::uuid)
     	"#,
    )
    .execute(pool)
    .await
    .unwrap();

    (tenant_a, tenant_b)
}

#[sqlx::test]
async fn e2e_proof_to_token_to_rls(pool: PgPool) {
    // 1. Mock WebCrypto: the client generates a key pair.
    let client = Client::new();
    let jkt = compute_jwk_thumbprint(&client.jwk).unwrap();

    // 2. The issuer mints an access token bound to that key,
    // carrying the tenant id as an application claim.
    let config = DpopConfig::builder()
        .public_url(PUBLIC_URL)
        .issuer(PUBLIC_URL)
        .audience("api")
        .signer(TokenSigner::symmetric(b"test-secret-key-must-be-at-least-32-bytes").unwrap())
        .build()
        .unwrap();

    let (tenant_a, tenant_b) = setup_rls(&pool).await;

    let mut extra = serde_json::Map::new();
    extra.insert(
        "tenant_id".to_string(),
        serde_json::json!(tenant_a.to_string()),
    );
    let token = issue_access_token(
        &config.signer,
        &config.issuer,
        &config.audience,
        Duration::from_secs(900),
        "user-1",
        &jkt,
        extra,
    )
    .unwrap();

    // 3. The client builds a DPoP proof for a resource
    // request (with `ath`), and the server validates it end-to-end.
    let jti_cache = create_jti_cache(Duration::from_secs(300));
    let nonce_cache = create_nonce_cache();
    let proof = client.proof("GET", "https://example.com/tickets", Some(&token));

    let validated = validate_dpop_proof(ValidationContext {
        proof: &proof,
        expected_htm: "GET",
        expected_htu: "https://example.com/tickets",
        access_token: Some(&token),
        nonce_required: false,
        clock_skew: config.clock_skew,
        allowed_algs: &config.allowed_algs,
        jti_cache: &jti_cache,
        nonce_cache: &nonce_cache,
    })
    .await
    .unwrap();

    // The proof is bound to the same key that the token is bound to.
    assert_eq!(validated.jwk_thumbprint, jkt);

    // 4. Tenant isolation: a TenantTx scoped to tenant A sees only
    // A's rows, and never B's.
    let mut tx = TenantTx::begin(&pool, tenant_a).await.unwrap();

    sqlx::query(
        r#"
     	SET LOCAL ROLE dpop_app
     	"#,
    )
    .execute(&mut *tx)
    .await
    .unwrap();

    let _titles: Vec<String> = sqlx::query_scalar(
        r#"
     	SELECT title FROM demo_tickets
      	ORDER BY title
     	"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();

    tx.rollback().await.unwrap();

    // And tenant B sees only its own.
    let mut tx = TenantTx::begin(&pool, tenant_b).await.unwrap();
    sqlx::query(
        r#"
     	SET LOCAL ROLE dpop_app
     	"#,
    )
    .execute(&mut *tx)
    .await
    .unwrap();

    let titles: Vec<String> = sqlx::query_scalar(
        r#"
     	SELECT title FROM demo_tickets
      	ORDER BY title
     	"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();

    assert_eq!(titles, vec!["B ticket".to_string()]);
}
