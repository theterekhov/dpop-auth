//! Authentication service: register, login, refresh (RTR), logout.

use std::{net::IpAddr, sync::Arc};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use moka::future::Cache;
use sqlx::{PgConnection, types::ipnetwork::IpNetwork};
use tracing::{Span, instrument};
use uuid::Uuid;

use crate::{
    DpopConfig,
    crypto::hash_token,
    store::{
        error::ServiceError,
        models::{CreateRefreshTokenParams, UserRow},
        password, repo,
    },
};

/// Refresh-secret length in bytes (256 bits of entropy).
const REFRESH_SECRET_LEN: usize = 32;

/// Token type per RFC 9449: access tokens are DPoP-bound.
const TOKEN_TYPE: &str = "DPoP";

/// Maximum capacity of the refresh-token grace-period cache.
const GRACE_CAPACITY: u64 = 100_000;

/// Parameters required to register a new user in [`AuthService::register`].
///
/// Encapsulates user identity, credentials, DPoP key binding, and audit
/// metadata into a single parameter struct to keep function signatures clean.
pub struct RegisterParams<'a> {
    /// The type of identifier being registered (e.g., `"email"`, `"username"`, `"phone"`).
    pub kind: &'a str,

    /// The raw identifier value (e.g., `"john@example.com"`).
    ///
    /// Normalized and stored according to application-level identifier rules.
    pub value: &'a str,

    /// Plaintext password provided by the user.
    ///
    /// Hashed asynchronously with Argon2id prior to persistence.
    pub password: &'a str,

    /// Display or full name pf the user.
    pub name: &'a str,

    /// JWK Thumbprint (RFC 7638 `jkt`) derived from the client's DPoP public key.
    ///
    /// Binds the initial session (and issued access/refresh tokens) to the client's key pair.
    pub jkt: &'a str,

    /// Remote IP address of the client submitting the registration request.
    ///
    /// Recorded in `dpop_login_attempts` for audit and rate-limiting purposes.
    pub client_ip: IpAddr,

    /// Optional `User-Agent` HTTP header value for session tracking.
    pub user_agent: Option<String>,
}

/// An access + refresh token pair issued on register/login/refresh.
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// DPoP-bound access token (short-lived).
    pub access_token: String,
    /// Raw refresh secret, delivered to the client exactly once.
    pub refresh_token: String,
    /// Token type (`DPoP`).
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
}

/// The outcome of a login attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoginOutcome {
    /// Password accepted, a token pair was issued.
    Success {
        /// The issued tokens.
        tokens: TokenPair,
    },
    /// Password accepted, but a second factor is required.
    Requires2fa,
}

/// Replacement pair cached during the rotation grace window.
#[derive(Clone)]
struct ReplacementTokens {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

/// Grace cache: `(fam, old_token_hash)` -> replacement pair.
type GraceCache = Cache<(Uuid, String), ReplacementTokens>;

/// High-level authentication service over the `dpop_*` schema.
pub struct AuthService {
    pool: sqlx::PgPool,
    config: Arc<DpopConfig>,
    /// A valid Argon2 hash used to equalize timing for unknown users.
    dummy_hash: String,
    grace_cache: GraceCache,
}

/// Computes a normalized SHA-256 hash of the identifier for audit spans.
///
/// Combines `kind` and `value` (both lowercased, separated by `:`) prior to
/// hashing via [`hash_token`]. This prevents cross-kind identifier collisions
/// while avoiding the leakage of raw Personally Identifiable Information (PII)
/// into telemetry and structured logs.
fn identifier_hash(kind: &str, value: &str) -> String {
    let combined = format!("{}:{}", kind.to_lowercase(), value.to_lowercase());
    hash_token(combined.as_bytes())
}

/// Generate a fresh refresh secret: base64url(32 random bytes) = 43 chars.
fn new_refresh_secret() -> Result<String, ServiceError> {
    let mut bytes = [0_u8; REFRESH_SECRET_LEN];
    getrandom::fill(&mut bytes).map_err(|e| ServiceError::Internal(e.to_string()))?;

    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

impl AuthService {
    /// Create the service.
    ///
    /// Pre-computes the timing-equalizing dummy hash once using Argon2id.
    /// This prevents side-channel user enumeration attacks on the login path.
    pub fn new(pool: sqlx::PgPool, config: DpopConfig) -> Self {
        let dummy_hash = password::hash_password("dpop-auth-timing-dummy").unwrap_or_default();
        let grace_cache = Cache::builder()
            .time_to_live(config.grace_period)
            .max_capacity(GRACE_CAPACITY)
            .build();

        Self {
            pool,
            config: Arc::new(config),
            dummy_hash,
            grace_cache,
        }
    }

    /// Calculate the expiration timestamp for a brand-new refresh token.
    fn refresh_expiry(&self) -> DateTime<Utc> {
        let ttl = self.config.refresh_token_ttl.as_secs() as i64;
        Utc::now() + chrono::Duration::seconds(ttl)
    }

    /// Issue a DPoP-bound access token for a user.
    fn issue_access_token(&self, user: &UserRow, jkt: &str) -> Result<String, ServiceError> {
        let mut extra = serde_json::Map::new();
        extra.insert("name".to_string(), user.name.clone().into());

        crate::token::issue_access_token(
            &self.config.signer,
            &self.config.issuer,
            &self.config.audience,
            self.config.access_token_ttl,
            &user.public_id.to_string(),
            jkt,
            extra,
        )
        .map_err(|e| ServiceError::Internal(e.to_string()))
    }

    /// Persist a new refresh token and issue the corresponding DPoP access token.
    async fn issue_session(
        &self,
        conn: &mut PgConnection,
        user: &UserRow,
        jkt: &str,
        user_agent: Option<String>,
    ) -> Result<TokenPair, ServiceError> {
        let refresh_token = new_refresh_secret()?;
        let token_hash = hash_token(refresh_token.as_bytes());

        repo::create_refresh_token(
            conn,
            CreateRefreshTokenParams {
                user_id: user.id,
                token_hash,
                fam: Uuid::new_v4(),
                dpop_jkt: jkt.to_string(),
                user_agent,
                expires_at: self.refresh_expiry(),
            },
        )
        .await?;

        let access_token = self.issue_access_token(user, jkt)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: TOKEN_TYPE,
            expires_in: self.config.access_token_ttl.as_secs(),
        })
    }

    /// Resolve a user by identifier and verify the password (constant-time behavior).
    async fn authenticate_user(
        &self,
        conn: &mut PgConnection,
        kind: &str,
        value: &str,
        password: &str,
        client_ip: IpAddr,
    ) -> Result<UserRow, ServiceError> {
        let opt_user = repo::find_user_by_identifier(conn, kind, value).await?;

        // Always execute one full Argon2 verification to prevent timing attacks.
        let hash = opt_user
            .as_ref()
            .map(|u| u.password_hash.clone())
            .unwrap_or_else(|| self.dummy_hash.clone());

        let valid = password::verify_password_async(password.to_string(), hash).await?;

        match opt_user {
            Some(user) if valid => Ok(user),
            Some(_) => {
                repo::record_login_attempt(
                    conn,
                    kind,
                    value,
                    IpNetwork::from(client_ip),
                    false,
                    Some("wrong_password"),
                )
                .await
                .ok();

                Err(ServiceError::Unauthorized)
            }
            None => {
                repo::record_login_attempt(
                    conn,
                    kind,
                    value,
                    IpNetwork::from(client_ip),
                    false,
                    Some("user_not_found"),
                )
                .await
                .ok();

                Err(ServiceError::Unauthorized)
            }
        }
    }

    /// Register a new user, create their primary identifier, and issue an initial token pair.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::RegistrationDisabled`] is self-registration is disabled.
    /// Returns [`ServiceError::Conflict`] if the given identifier is already registered.
    /// Returns [`ServiceError::Internal`] on password hashing or database execution failures.
    #[instrument(
    	name = "auth.register",
     	skip_all,
      	fields(
       		identifier_hash = tracing::field::Empty,
       		user.id = tracing::field::Empty,
       		outcome = tracing::field::Empty,
       	)
    )]
    pub async fn register(&self, params: RegisterParams<'_>) -> Result<TokenPair, ServiceError> {
        let span = Span::current();

        if !self.config.allow_registration {
            span.record("outcome", "disabled");

            return Err(ServiceError::RegistrationDisabled);
        }

        span.record(
            "identifier_hash",
            identifier_hash(params.kind, params.value),
        );

        let password_hash = password::hash_password_async(params.password.to_string()).await?;

        let mut tx = self.pool.begin().await?;

        let user =
            repo::create_user(&mut tx, params.name, &password_hash, Some(Utc::now())).await?;

        if let Err(e) = repo::create_identifier(
            &mut tx,
            user.id,
            params.kind,
            params.value,
            true,
            Some(Utc::now()),
        )
        .await
        {
            // tx is dropped here -> automatic ROLLBACK (user is not persisted).
            return Err(match e {
                sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                    ServiceError::Conflict(format!("{} already registered", params.kind))
                }
                other => ServiceError::Internal(other.to_string()),
            });
        }

        repo::update_last_login_at(&mut tx, user.id).await?;

        let refresh_token = new_refresh_secret()?;
        let token_hash = hash_token(refresh_token.as_bytes());

        repo::create_refresh_token(
            &mut tx,
            CreateRefreshTokenParams {
                user_id: user.id,
                token_hash,
                fam: Uuid::new_v4(),
                dpop_jkt: params.jkt.to_string(),
                user_agent: params.user_agent,
                expires_at: self.refresh_expiry(),
            },
        )
        .await?;

        repo::record_login_attempt(
            &mut tx,
            params.kind,
            params.value,
            IpNetwork::from(params.client_ip),
            true,
            None,
        )
        .await
        .ok();

        tx.commit().await?;

        span.record("user.id", tracing::field::display(user.public_id));
        span.record("outcome", "created");

        let access_token = self.issue_access_token(&user, params.jkt)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: TOKEN_TYPE,
            expires_in: self.config.access_token_ttl.as_secs(),
        })
    }

    /// Authenticate a user with an identifier and password.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unauthorized`] on missing user or invalid password.
    /// Returns [`ServiceError::Internal`] on database connection or query failures.
    #[instrument(
    	name = "auth.login",
     	skip_all,
      	fields(
       		identifier_hash = tracing::field::Empty,
       		user.id = tracing::field::Empty,
       		outcome = tracing::field::Empty,
       	)
    )]
    pub async fn login(
        &self,
        kind: &str,
        value: &str,
        password: &str,
        jkt: &str,
        client_ip: IpAddr,
        user_agent: Option<String>,
    ) -> Result<LoginOutcome, ServiceError> {
        let span = Span::current();

        span.record("identifier_hash", identifier_hash(kind, value));

        let mut conn = self.pool.acquire().await?;

        let user = self
            .authenticate_user(&mut conn, kind, value, password, client_ip)
            .await?;

        span.record("user.id", tracing::field::display(user.public_id));

        if user.totp_enabled {
            span.record("outcome", "requires_2fa");
            return Ok(LoginOutcome::Requires2fa);
        }

        repo::update_last_login_at(&mut conn, user.id).await.ok();
        repo::record_login_attempt(
            &mut conn,
            kind,
            value,
            IpNetwork::from(client_ip),
            true,
            None,
        )
        .await
        .ok();

        let tokens = self
            .issue_session(&mut conn, &user, jkt, user_agent)
            .await?;

        span.record("outcome", "success");

        Ok(LoginOutcome::Success { tokens })
    }

    /// Rotate a refresh token (RTR) and issue a fresh DPoP-bound token pair.
    ///
    /// Implements Refresh Token Rotation with reuse detection and a grace period
    /// in accordance with RFC 9700.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unauthorized`] if:
    /// - The token is invalid, expired, or previously revoked outside the grace window.
    /// - The client's DPoP thumbprint does not match the token's bound 'jkt'.
    /// - Token reuse is detected (revoking the entire token family).
    #[instrument(
    	name = "auth.refresh",
     	skip_all,
      	fields(
       		user.id = tracing::field::Empty,
       		outcome = tracing::field::Empty,
       	)
    )]
    pub async fn refresh(
        &self,
        refresh_token: &str,
        jkt: &str,
        user_agent: Option<String>,
    ) -> Result<TokenPair, ServiceError> {
        let span = Span::current();

        let token_hash = hash_token(refresh_token.as_bytes());

        let mut tx = self.pool.begin().await?;

        // Atomic rotation: exactly one concurrent request wins this revoke.
        // The `WHERE revoked_at IS NULL` guard is a compare-and-swap (CAS).
        let row = repo::revoke_refresh_token_if_active(&mut tx, &token_hash).await?;

        let Some(row) = row else {
            // Already revoked or unknown: distinguish benign grace retry from malicious reuse.
            let existing = repo::find_refresh_token_by_hash(&mut tx, &token_hash).await?;

            match existing {
                Some(existing) => {
                    let cache_key = (existing.fam, token_hash);

                    if let Some(cached) = self.grace_cache.get(&cache_key).await {
                        span.record("user.id", tracing::field::display(existing.user_id));
                        span.record("outcome", "grace");

                        return Ok(TokenPair {
                            access_token: cached.access_token,
                            refresh_token: cached.refresh_token,
                            token_type: TOKEN_TYPE,
                            expires_in: cached.expires_in,
                        });
                    }

                    span.record("user.id", tracing::field::display(existing.user_id));
                    span.record("outcome", "reuse_detected");

                    repo::revoke_refresh_token_family(&mut tx, existing.fam).await?;

                    tx.commit().await?;

                    return Err(ServiceError::Unauthorized);
                }
                None => {
                    span.record("outcome", "not_found");

                    return Err(ServiceError::Unauthorized);
                }
            }
        };

        // The token was active and the CAS above just revoked it.
        // On expired or key-mismatch branches, dropping the transaction automatically
        // rolls back the revocation, keeping the token intact for the legitimate owner.
        if row.expires_at <= Utc::now() {
            span.record("user.id", tracing::field::display(row.user_id));
            span.record("outcome", "expired");

            return Err(ServiceError::Unauthorized);
        }

        if row.dpop_jkt != jkt {
            span.record("user_id", tracing::field::display(row.user_id));
            span.record("outcome", "dpop_key_mismatch");

            return Err(ServiceError::Unauthorized);
        }

        let user = repo::find_user_by_id(&mut tx, row.user_id)
            .await?
            .ok_or(ServiceError::Unauthorized)?;

        span.record("user.id", tracing::field::display(user.public_id));

        let new_refresh_token = new_refresh_secret()?;
        let new_token_hash = hash_token(new_refresh_token.as_bytes());

        repo::create_refresh_token(
            &mut tx,
            CreateRefreshTokenParams {
                user_id: row.user_id,
                token_hash: new_token_hash,
                fam: row.fam,
                dpop_jkt: jkt.to_string(),
                user_agent,
                expires_at: row.expires_at,
            },
        )
        .await?;

        let access_token = self.issue_access_token(&user, jkt)?;
        let expires_in = self.config.access_token_ttl.as_secs();

        self.grace_cache
            .insert(
                (row.fam, token_hash),
                ReplacementTokens {
                    access_token: access_token.clone(),
                    refresh_token: new_refresh_token.clone(),
                    expires_in,
                },
            )
            .await;

        tx.commit().await?;

        span.record("outcome", "refreshed");

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh_token,
            token_type: TOKEN_TYPE,
            expires_in,
        })
    }

    /// Explicitly revoke a refresh token and terminate the corresponding session.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Internal`] if the database query fails.
    #[instrument(
    	name = "auth.logout",
     	skip_all,
      	fields(outcome = tracing::field::Empty)
    )]
    pub async fn logout(&self, refresh_token: &str) -> Result<(), ServiceError> {
        let span = Span::current();
        let token_hash = hash_token(refresh_token.as_bytes());

        let mut conn = self.pool.acquire().await?;
        repo::revoke_refresh_token_by_hash(&mut conn, &token_hash).await?;

        span.record("outcome", "revoked");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use sqlx::PgPool;

    use crate::TokenSigner;

    use super::*;

    const TEST_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const TEST_PASSWORD: &str = "correct horse battery staple";

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    fn build_service(
        pool: &PgPool,
        grace: Duration,
        refresh_ttl: Duration,
        allow_registration: bool,
    ) -> AuthService {
        let signer = TokenSigner::symmetric(b"test-secret-key");
        let config = DpopConfig::builder()
            .public_url("https://example.com")
            .signer(signer)
            .grace_period(grace)
            .refresh_token_ttl(refresh_ttl)
            .allow_registration(allow_registration)
            .build()
            .unwrap();

        AuthService::new(pool.clone(), config)
    }

    fn service(pool: &PgPool) -> AuthService {
        build_service(
            pool,
            Duration::from_secs(5),
            Duration::from_secs(30 * 24 * 60 * 60),
            true,
        )
    }

    async fn register_user(service: &AuthService) -> TokenPair {
        service
            .register(RegisterParams {
                kind: "email",
                value: "john@example.com",
                password: TEST_PASSWORD,
                name: "John",
                jkt: TEST_JKT,
                client_ip: test_ip(),
                user_agent: None,
            })
            .await
            .unwrap()
    }

    async fn refresh_expiry(pool: &PgPool, secret: &str) -> DateTime<Utc> {
        let mut conn = pool.acquire().await.unwrap();

        repo::find_refresh_token_by_hash(&mut conn, &hash_token(secret.as_bytes()))
            .await
            .unwrap()
            .unwrap()
            .expires_at
    }

    // register

    #[sqlx::test]
    async fn register_creates_user_and_issues_tokens(pool: PgPool) {
        let service = service(&pool);
        let tokens = register_user(&service).await;

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "DPoP");
        assert!(tokens.expires_in > 0);

        let mut conn = pool.acquire().await.unwrap();
        let user = repo::find_user_by_identifier(&mut conn, "email", "john@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.name, "John");
    }

    #[sqlx::test]
    async fn register_conflicts_on_duplicate_identifier(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let err = service
            .register(RegisterParams {
                kind: "email",
                value: "john@example.com",
                password: TEST_PASSWORD,
                name: "John",
                jkt: TEST_JKT,
                client_ip: test_ip(),
                user_agent: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Conflict(_)));
    }

    #[sqlx::test]
    async fn register_conflict_is_case_insensitive(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let err = service
            .register(RegisterParams {
                kind: "email",
                value: "JOHN@EXAMPLE.COM",
                password: TEST_PASSWORD,
                name: "John",
                jkt: TEST_JKT,
                client_ip: test_ip(),
                user_agent: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Conflict(_)));
    }

    #[sqlx::test]
    async fn register_disabled_returns_error(pool: PgPool) {
        let service = build_service(
            &pool,
            Duration::from_secs(5),
            Duration::from_secs(30 * 24 * 60 * 60),
            false,
        );

        let err = service
            .register(RegisterParams {
                kind: "email",
                value: "john@example.com",
                password: TEST_PASSWORD,
                name: "John",
                jkt: TEST_JKT,
                client_ip: test_ip(),
                user_agent: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::RegistrationDisabled));
    }

    // login

    #[sqlx::test]
    async fn login_success_issues_tokens(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let outcome = service
            .login(
                "email",
                "john@example.com",
                TEST_PASSWORD,
                TEST_JKT,
                test_ip(),
                None,
            )
            .await
            .unwrap();

        match outcome {
            LoginOutcome::Success { tokens } => assert!(!tokens.access_token.is_empty()),
            _ => panic!("expected Success"),
        }
    }

    #[sqlx::test]
    async fn login_wrong_password_returns_unauthorized(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let err = service
            .login(
                "email",
                "john@example.com",
                "wrong_password",
                TEST_JKT,
                test_ip(),
                None,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Unauthorized));
    }

    #[sqlx::test]
    async fn login_unknown_identifier_returns_unauthorized(pool: PgPool) {
        let service = service(&pool);

        let err = service
            .login(
                "email",
                "nobody@example.com",
                TEST_PASSWORD,
                TEST_JKT,
                test_ip(),
                None,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Unauthorized));
    }

    #[sqlx::test]
    async fn login_is_case_insensitive(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let outcome = service
            .login(
                "email",
                "JOHN@EXAMPLE.COM",
                TEST_PASSWORD,
                TEST_JKT,
                test_ip(),
                None,
            )
            .await
            .unwrap();

        assert!(matches!(outcome, LoginOutcome::Success { .. }));
    }

    #[sqlx::test]
    async fn login_requires_2fa_when_totp_enabled(pool: PgPool) {
        let service = service(&pool);
        register_user(&service).await;

        let mut conn = pool.acquire().await.unwrap();

        let user = repo::find_user_by_identifier(&mut conn, "email", "john@example.com")
            .await
            .unwrap()
            .unwrap();

        sqlx::query!(
            r#"
         	UPDATE dpop_users SET totp_enabled = TRUE
          	WHERE id = $1
         	"#,
            user.id
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        let outcome = service
            .login(
                "email",
                "john@example.com",
                TEST_PASSWORD,
                TEST_JKT,
                test_ip(),
                None,
            )
            .await
            .unwrap();

        assert!(matches!(outcome, LoginOutcome::Requires2fa));
    }

    // refresh

    #[sqlx::test]
    async fn refresh_rotates_token(pool: PgPool) {
        let service = service(&pool);
        let old = register_user(&service).await;

        let new = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap();

        assert_ne!(new.refresh_token, old.refresh_token);

        // old is revoked, new is active
        let mut conn = pool.acquire().await.unwrap();

        let old_row =
            repo::find_refresh_token_by_hash(&mut conn, &hash_token(old.refresh_token.as_bytes()))
                .await
                .unwrap()
                .unwrap();
        assert!(old_row.revoked_at.is_some());

        let new_row =
            repo::find_refresh_token_by_hash(&mut conn, &hash_token(new.refresh_token.as_bytes()))
                .await
                .unwrap()
                .unwrap();
        assert!(new_row.revoked_at.is_none());
        assert_eq!(new_row.fam, old_row.fam);
    }

    #[sqlx::test]
    async fn refresh_reuse_revokes_family(pool: PgPool) {
        // grace = 1ms so the grace entry expires quickly and we hit reuse.
        let service = build_service(
            &pool,
            Duration::from_millis(1),
            Duration::from_secs(38 * 24 * 60 * 60),
            true,
        );
        let old = register_user(&service).await;

        let new = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let err = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::Unauthorized));

        // the whole family is revoked, including the replacement
        let mut conn = pool.acquire().await.unwrap();
        let new_row =
            repo::find_refresh_token_by_hash(&mut conn, &hash_token(new.refresh_token.as_bytes()))
                .await
                .unwrap()
                .unwrap();
        assert!(new_row.revoked_at.is_some());
    }

    #[sqlx::test]
    async fn refresh_grace_returns_same_replacement(pool: PgPool) {
        let service = service(&pool);
        let old = register_user(&service).await;

        let first = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap();

        // immediate reuse within the 5s grace window -> same replacement, no reuse
        let second = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap();

        assert_eq!(second.refresh_token, first.refresh_token);
    }

    #[sqlx::test]
    async fn refresh_inherits_lifetime(pool: PgPool) {
        let service = build_service(&pool, Duration::from_secs(5), Duration::from_secs(60), true);
        let old = register_user(&service).await;

        let old_expires = refresh_expiry(&pool, &old.refresh_token).await;

        tokio::time::sleep(Duration::from_secs(1)).await;

        let new = service
            .refresh(&old.refresh_token, TEST_JKT, None)
            .await
            .unwrap();

        let new_expires = refresh_expiry(&pool, &new.refresh_token).await;

        // lifetime is inherited, not reset (RFC 9700 section 4.14)
        assert_eq!(new_expires, old_expires);
    }

    #[sqlx::test]
    async fn refresh_dpop_key_mismatch_rejected(pool: PgPool) {
        let service = service(&pool);
        let old = register_user(&service).await;

        let err = service
            .refresh(&old.refresh_token, "some-other-jkt", None)
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Unauthorized));
    }

    #[sqlx::test]
    async fn refresh_unknown_token_rejected(pool: PgPool) {
        let service = service(&pool);

        let err = service
            .refresh("not-a-real-refersh-token", TEST_JKT, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ServiceError::Unauthorized));
    }

    // logout

    #[sqlx::test]
    async fn logout_revokes_token(pool: PgPool) {
        let service = service(&pool);
        let tokens = register_user(&service).await;

        service.logout(&tokens.refresh_token).await.unwrap();

        let err = service
            .refresh(&tokens.refresh_token, TEST_JKT, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::Unauthorized));
    }
}
