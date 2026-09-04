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
#[cfg(feature = "totp")]
use crate::{
    cache::{TotpReplayCache, create_totp_replay_cache},
    store::totp::{self, set_pending_totp_secret},
    totp::{
        TotpSetup, generate_recovery_codes, generate_setup, hash_recovery_code, is_recovery_code,
        setup_from_secret, verify_code,
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
    #[cfg(feature = "totp")]
    totp_replay_cache: TotpReplayCache,
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
            #[cfg(feature = "totp")]
            totp_replay_cache: create_totp_replay_cache(),
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

/// The specific category of second-factor credential verified during authentication.
#[cfg(feature = "totp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactorKind {
    /// A standard time-based one-time password generated by an authenticator
    /// application (RFC 6238).
    Totp,
    /// A single-use backup recovery code that was atomically consumed and invalidated
    /// upon verification.
    RecoveryCode,
}

/// Internal classification outcome for a single TOTP evaluation attempt.
#[cfg(feature = "totp")]
enum TotpCheck {
    /// Code matched the expected HMAC-SHA1 value within the time window
    /// and has not been used yet.
    Valid,
    /// Code did not match the expected value or was malformed.
    Invalid,
    /// Code was cryptographically valid but was already used
    /// within the current time window.
    Replayed,
}

#[cfg(feature = "totp")]
impl AuthService {
    /// Verifies a time-based one-time password with replay protection (RFC 6238 section 5.2).
    ///
    /// Checks the code against the shared secret within the permitted time-drift window.
    /// If cryptographically valid, atomically attempts to record `(user_id, code)` into
    /// the replay cache using an entry-level lock to eliminate TOCTOU race conditions.
    ///
    /// # Returns
    ///
    /// * [`TotpCheck::Valid`] - The token is cryptographically valid, fresh,
    ///   and successfully claimed.
    /// * [`TotpCheck::Invalid`] - The code did not match the shared secret or was malformed.
    /// * [`TotpCheck::Replayed`] - The code is valid but has already been submitted within
    ///   the active window.
    ///
    /// # Errors
    ///
    /// This function returns `Ok(_)` for valid, invalid or replayed outcomes. The `Result`
    /// wrapper is retained for interface consistency with the async service pipeline.
    async fn verify_totp_once(
        &self,
        user_id: Uuid,
        secret: &str,
        code: &str,
    ) -> Result<TotpCheck, ServiceError> {
        if !verify_code(secret, code) {
            return Ok(TotpCheck::Invalid);
        }

        let key = (user_id, code.trim().to_string());

        let entry = self
            .totp_replay_cache
            .entry_by_ref(&key)
            .or_insert(())
            .await;

        if entry.is_fresh() {
            Ok(TotpCheck::Valid)
        } else {
            Ok(TotpCheck::Replayed)
        }
    }

    /// Starts (or resumes) the two-factor authentication (2FA) enrollment flow.
    ///
    /// The generated secret is placed into a temporary draft column
    /// (`totp_pending_secret`) with a 10-minute TTL and does not touch the active
    /// `totp_secret`. The draft is only promoted to the active secret upon successful code
    /// verification in [`Self::confirm_2fa`].
    ///
    /// # Idempotent Setup / Tab Refresh
    ///
    /// If a live pending draft already exists (within the 10-minute TTL), this function
    /// reconstructs and returns **same** setup data and QR code rather than generating
    /// a new secret. This allows the user to refresh or reopen the setup page without
    /// invalidating the QR code already scanned by their authenticator app.
    ///
    /// # Parameters
    ///
    /// * `user_id` - Primary key (`UUIDv7`) of the user enrolling in 2FA.
    /// * `issuer` - Provider/Service name shown in the authenticator app (e.g., `"MyApp"`).
    /// * `account_name` - User identifier shown in the authenticator app (e.g., email or username).
    ///
    /// # Errors
    ///
    /// * [`ServiceError::Unauthorized`] - The specified user does not exists or
    ///   has been soft-deleted.
    /// * [`ServiceError::Conflict`] - 2FA is already confirmed and active for this user.
    /// * [`ServiceError::Internal`] - QR code rendering, secret generation, or database operations
    ///   failed.
    pub async fn setup_2fa(
        &self,
        user_id: Uuid,
        issuer: &str,
        account_name: &str,
    ) -> Result<TotpSetup, ServiceError> {
        let mut conn = self.pool.acquire().await?;

        let user = repo::find_user_by_id(&mut conn, user_id)
            .await?
            .ok_or(ServiceError::Unauthorized)?;

        // Do not start a draft for an already-enrolled user: 2FA is already on,
        // there is nothing to draft. `setup_2fa` on an enrolled user writes
        // nothing (and the frontend should already show "2FA enabled").
        if user.totp_enabled {
            return Err(ServiceError::Conflict("2FA already enabled".into()));
        }

        // A live draft (within TTL) already exists: re-show the SAME QR.
        // Regenerating here would orphan the phone (its already-scanned code
        // would no longer match) and a hard `Conflict` would lock the user out
        // of the QR until the TTL expires. Returning the existing draft keeps
        // both the resume path and the already-scanned code valid.
        if let Some(existing) = totp::get_pending_totp_secret(&mut conn, user_id).await? {
            return setup_from_secret(&existing, issuer, account_name)
                .map_err(|e| ServiceError::Internal(e.to_string()));
        }

        let setup = generate_setup(issuer, account_name)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;

        set_pending_totp_secret(&mut conn, user_id, &setup.secret_base32).await?;

        Ok(setup)
    }

    /// Verifies the initial TOTP code to complete 2FA activation and issues
    /// recovery codes.
    ///
    /// Reads the pending draft secret, checks that its 10-minute TTL has not expired,
    /// and verifies the submitted `code`. Upon success, executes an atomic transaction that:
    /// 1. Promotes `totp_pending_secret` to active `totp_secret`, set `totp_enabled = TRUE`,
    ///    and clears the pending draft.
    /// 2. Invalidates any existing recovery codes previously issued for this user.
    /// 3. Stores the cryptographic hashes of 10 freshly generated recovery codes.
    ///
    /// Returns the plaintext recovery codes. **These codes are shown to the user exactly once.**
    ///
    /// # Parameters
    ///
    /// * `user_id` - Primary key (`UUIDv7`) of the user confirming 2FA.
    /// * `code` - 6-digit numeric TOTP string produced by the authenticator app.
    ///
    /// # Errors
    ///
    /// * [`ServiceError::Unauthorized`] - The user does not exist or the
    ///   submitted `code` is invalid.
    /// * [`ServiceError::Conflict`] - 2FA is already enabled, or the pending draft expired /
    ///   does not exist.
    /// * [`ServiceError::Internal`] - CSPRNG failure, database queries, or transaction
    ///   execution failed.
    pub async fn confirm_2fa(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<Vec<String>, ServiceError> {
        let mut conn = self.pool.acquire().await?;

        let user = repo::find_user_by_id(&mut conn, user_id)
            .await?
            .ok_or(ServiceError::Unauthorized)?;

        if user.totp_enabled {
            return Err(ServiceError::Conflict("2FA already enabled".into()));
        }

        // Draft + TTL check live in one place: `None` means no draft or expired.
        let Some(secret) = totp::get_pending_totp_secret(&mut conn, user_id).await? else {
            return Err(ServiceError::Conflict(
                "setup expired, run setup_2fa again".into(),
            ));
        };

        if !verify_code(&secret, code) {
            return Err(ServiceError::Unauthorized);
        }

        // Propagate entropy failures instead of silently issuing empty codes.
        let recovery_codes =
            generate_recovery_codes(10).map_err(|e| ServiceError::Internal(e.to_string()))?;
        let hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| hash_recovery_code(c))
            .collect();

        // Activation + recovery codes commit together (principle 3).
        let mut tx = self.pool.begin().await?;

        totp::activate_totp(&mut tx, user.id).await?;
        totp::invalidate_recovery_codes_for_user(&mut tx, user.id).await?;
        totp::create_recovery_codes(&mut tx, user.id, &hashes).await?;

        tx.commit().await?;

        Ok(recovery_codes)
    }

    /// Validates a second-factor credential (TOTP code or single-use recovery code)
    /// for an active user.
    ///
    /// Distinguishes between TOTP codes and recovery codes via [`crate::totp::is_recovery_code`]:
    /// * **Recovery code**: The hash is verified against `dpop_recovery_codes` scoped strictly
    ///   to `user_id`. If valid, the code immediately consumed (deleted/burned) in the database.
    /// * **TOTP Code**: Checked against RFC 6238 rules with replay protection enforced via
    ///   in-memory cache.
    ///
    /// # Parameters
    ///
    /// * `user_id` - Primary key (UUIDv7) of the user verifying the credential.
    /// * `code` - Submitted second-factor string (either a 6-digit TOTP token or an
    ///   alphanumeric recovery code).
    ///
    /// # Returns
    ///
    /// * [`SecondFactorKind::RecoveryCode`] - A single use recovery code was consumed
    ///   (caller should display a warning/remaining count).
    /// * [`SecondFactorKind::Totp`] - A standard time-based TOTP code was accepted.
    ///
    /// # Errors
    ///
    /// * [`ServiceError::Unauthorized`] - The user does not exist, the code is incorrect,
    ///   or a TOTP replay was detected.
    /// * [`ServiceError::Conflict`] - 2FA is not enabled for this user.
    /// * [`ServiceError::Internal`] - A database query or pool acquisition failed.
    pub async fn verify_2fa_code(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<SecondFactorKind, ServiceError> {
        let mut conn = self.pool.acquire().await?;

        let user = repo::find_user_by_id(&mut conn, user_id)
            .await?
            .ok_or(ServiceError::Unauthorized)?;

        if !user.totp_enabled {
            return Err(ServiceError::Conflict("2FA is not enabled".into()));
        }

        if is_recovery_code(code) {
            let hash = hash_recovery_code(code);

            // Ownership is checked inside the SQL (`WHERE user_id = $1`), so a
            // code belonging to another user is rejected without being burned.
            if totp::consume_recovery_code(&mut conn, user.id, &hash)
                .await?
                .is_some()
            {
                Ok(SecondFactorKind::RecoveryCode)
            } else {
                Err(ServiceError::Unauthorized)
            }
        } else {
            let secret = user
                .totp_secret
                .as_deref()
                .ok_or(ServiceError::Unauthorized)?;

            match self.verify_totp_once(user.id, secret, code).await? {
                TotpCheck::Valid => Ok(SecondFactorKind::Totp),
                TotpCheck::Invalid | TotpCheck::Replayed => Err(ServiceError::Unauthorized),
            }
        }
    }

    /// Disables two-factor authentication for an account after verifying a step-up code.
    ///
    /// Requires a valid TOTP or recovery code to prevent unauthorized deactivation.
    /// Upon successful verification, an atomic transaction:
    /// 1. Clears `totp_secret`, resets `totp_enabled` to `FALSE`, and nullifies timestamps.
    /// 2. Permanently deletes/invalidates all remaining recovery codes for the user.
    ///
    /// # Parameters
    ///
    /// * `user_id` - Primary key (`UUIDv7`) of the user disabling 2FA.
    /// * `code` - Step-up credential (valid TOTP code or unused recovery code).
    ///
    /// # Errors
    ///
    /// * [`ServiceError::Unauthorized`] - The user does not exist or the step-up code is invalid.
    /// * [`ServiceError::Conflict`] - 2FA is not currently enabled for this user.
    /// * [`ServiceError::Internal`] - A database transaction or query failed.
    pub async fn disable_2fa(&self, user_id: Uuid, code: &str) -> Result<(), ServiceError> {
        let mut conn = self.pool.acquire().await?;

        let user = repo::find_user_by_id(&mut conn, user_id)
            .await?
            .ok_or(ServiceError::Unauthorized)?;

        if !user.totp_enabled {
            return Err(ServiceError::Conflict("2FA is not enabled".into()));
        }

        self.verify_2fa_code(user_id, code).await?;

        let mut tx = self.pool.begin().await?;

        totp::disable_totp(&mut tx, user.id).await?;
        totp::invalidate_recovery_codes_for_user(&mut tx, user.id).await?;

        tx.commit().await?;

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

#[cfg(all(test, feature = "totp"))]
mod totp_tests {
    use std::net::Ipv4Addr;

    use sqlx::PgPool;
    use totp_rs::{Algorithm, Builder, Secret};

    use crate::{TokenSigner, store::totp::count_active_recovery_codes};

    use super::*;

    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const PASSWORD: &str = "correct horse battery staple";

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    fn service(pool: &PgPool) -> AuthService {
        let singer = TokenSigner::symmetric(b"test-secret-key");
        let config = DpopConfig::builder()
            .public_url("https://example.com")
            .signer(singer)
            .build()
            .unwrap();

        AuthService::new(pool.clone(), config)
    }

    async fn register(pool: &PgPool) -> UserRow {
        let service = service(pool);
        service
            .register(RegisterParams {
                kind: "email",
                value: "john@example.com",
                password: PASSWORD,
                name: "John",
                jkt: JKT,
                client_ip: test_ip(),
                user_agent: None,
            })
            .await
            .unwrap();

        let mut conn = pool.acquire().await.unwrap();
        repo::find_user_by_identifier(&mut conn, "email", "john@example.com")
            .await
            .unwrap()
            .unwrap()
    }

    fn current_code(secret_base32: &str) -> String {
        let secret = Secret::try_from_base32(secret_base32).unwrap();

        Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_secret(secret)
            .build()
            .unwrap()
            .generate_current()
            .to_string()
    }

    // Run setup + confirm for a user and return the freshly-issued recovery codes.
    async fn enroll(pool: &PgPool, user_id: Uuid) -> Vec<String> {
        let service = service(pool);
        let setup = service
            .setup_2fa(user_id, "Example", "john@example.com")
            .await
            .unwrap();
        let code = current_code(&setup.secret_base32);

        service.confirm_2fa(user_id, &code).await.unwrap()
    }

    #[sqlx::test]
    async fn setup_confirms_then_activates_2fa(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        // Phase 1: setup writes ONLY a pending draft, not the active secret.
        let setup = service
            .setup_2fa(user.id, "Example", "john@example.com")
            .await
            .unwrap();
        assert!(!setup.secret_base32.is_empty());

        let mut conn = pool.acquire().await.unwrap();

        let before = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!before.totp_enabled);
        assert!(
            before.totp_secret.is_none(),
            "active secret untouched by setup"
        );

        // Phase 2+3: confirm verifies the draft + TTL, then activates atomically.
        let code = current_code(&setup.secret_base32);
        let recovery_codes = service.confirm_2fa(user.id, &code).await.unwrap();

        assert_eq!(recovery_codes.len(), 10);
        assert!(recovery_codes.iter().all(|c| is_recovery_code(c)));

        let enabled = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(enabled.totp_enabled);
        assert!(enabled.totp_enabled_at.is_some());
        assert_eq!(
            enabled.totp_secret.as_deref(),
            Some(&setup.secret_base32[..])
        );
        assert!(
            enabled.totp_pending_secret.is_none(),
            "pending secret cleared after activation"
        );
    }

    #[sqlx::test]
    async fn confirm_2fa_rejects_wrong_code(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        service
            .setup_2fa(user.id, "Example", "john@example.com")
            .await
            .unwrap();
        assert!(matches!(
            service.confirm_2fa(user.id, "000000").await,
            Err(ServiceError::Unauthorized)
        ));

        let mut conn = pool.acquire().await.unwrap();

        let after = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!after.totp_enabled, "wrong code must not activate 2FA");
        assert!(after.totp_secret.is_none());
    }

    #[sqlx::test]
    async fn expired_draft_is_rejected(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        let setup = service
            .setup_2fa(user.id, "Example", "john@example.com")
            .await
            .unwrap();

        // Age the draft past the 10-minutes TTL directly in the DB.
        // Use an owner connection and drop it BEFORE calling confirm_2fa
        // (which acquires its own connection) - this avoids holding a pool slot
        // and any risk of pool exhaustion with a small `#[sqlx::test]` pool.
        {
            let mut conn = pool.acquire().await.unwrap();

            sqlx::query!(
                r#"
         	UPDATE dpop_users
          	SET totp_pending_at = now() - INTERVAL '11 minutes'
           	WHERE id = $1
         	"#,
                user.id
            )
            .execute(&mut *conn)
            .await
            .unwrap();
        } // conn dropped here

        let code = current_code(&setup.secret_base32);
        assert!(matches!(
            service.confirm_2fa(user.id, &code).await,
            Err(ServiceError::Conflict(_))
        ));

        let mut conn = pool.acquire().await.unwrap();

        let after = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!after.totp_enabled, "expired draft must not activate");
        assert!(after.totp_secret.is_none());
        assert!(after.totp_pending_secret.is_some());
        assert!(after.totp_pending_at.is_some());
    }

    #[sqlx::test]
    async fn setup_2fa_returns_same_live_draft(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        let first = service
            .setup_2fa(user.id, "Example", "john@example.com")
            .await
            .unwrap();
        let second = service
            .setup_2fa(user.id, "Example", "john@example.com")
            .await
            .unwrap();

        // A live draft (younger than TTL) is *resumed*, not replaced and not
        // blocked: the Same secret comes back, so a refreshed tab (F5) recovers
        // the QR the phone already scanned instead of failing with `Conflict.`
        assert_eq!(second.secret_base32, first.secret_base32);

        // The re-shown QR / draft is still valid for confirmation.
        let code = current_code(&second.secret_base32);
        let recovery_codes = service.confirm_2fa(user.id, &code).await.unwrap();
        assert_eq!(recovery_codes.len(), 10);
    }

    #[sqlx::test]
    async fn verify_2fa_code_rejects_replay(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        let recovery_codes = enroll(&pool, user.id).await;
        assert_eq!(recovery_codes.len(), 10);

        // The step-up code must be generated from the ACTIVE secret,
        // not a fresh draft: `setup_2fa` on an enrolled user writes nothing.
        let mut conn = pool.acquire().await.unwrap();

        let active_secret = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap()
            .totp_secret
            .clone()
            .unwrap();

        drop(conn);

        let step_up = current_code(&active_secret);
        assert_eq!(
            service.verify_2fa_code(user.id, &step_up).await.unwrap(),
            SecondFactorKind::Totp
        );
        assert!(matches!(
            service.verify_2fa_code(user.id, &step_up).await,
            Err(ServiceError::Unauthorized)
        ));
    }

    #[sqlx::test]
    async fn recovery_code_is_single_use(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        let recovery_codes = enroll(&pool, user.id).await;
        assert_eq!(recovery_codes.len(), 10);

        let used = service
            .verify_2fa_code(user.id, &recovery_codes[0])
            .await
            .unwrap();
        assert_eq!(used, SecondFactorKind::RecoveryCode);

        let again = service.verify_2fa_code(user.id, &recovery_codes[0]).await;
        assert!(matches!(again, Err(ServiceError::Unauthorized)));
    }

    #[sqlx::test]
    async fn disable_2fa_clears_state(pool: PgPool) {
        let user = register(&pool).await;
        let service = service(&pool);

        let recovery_codes = enroll(&pool, user.id).await;

        service
            .disable_2fa(user.id, &recovery_codes[0])
            .await
            .unwrap();

        let mut conn = pool.acquire().await.unwrap();

        let updated_user = repo::find_user_by_id(&mut conn, user.id)
            .await
            .unwrap()
            .unwrap();

        assert!(!updated_user.totp_enabled);
        assert!(updated_user.totp_secret.is_none());
        assert!(updated_user.totp_pending_secret.is_none());

        let active_recovery_codes = count_active_recovery_codes(&mut conn, user.id)
            .await
            .unwrap();
        assert_eq!(active_recovery_codes, 0);
    }
}
