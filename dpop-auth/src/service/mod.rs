//! High level authentication service: register, login, refresh (RTR), logout.
//!
//! - [`auth`] - core registration, authentication, and token rotation.
//! - [`totp`] - TOTP (2FA) setup, confirmation, and verification (`cfg(feature = "totp"))`).
//! - [`email`] - transactional email outbox worker.

use std::sync::Arc;

use moka::future::Cache;
use uuid::Uuid;

#[cfg(feature = "totp")]
use crate::cache::totp::{TotpReplayCache, create_totp_replay_cache};

use crate::{DpopConfig, crypto::password};

pub mod auth;

#[cfg(feature = "totp")]
pub mod totp;

#[cfg(all(feature = "email", feature = "postgres"))]
pub mod email;

pub use auth::{LoginOutcome, RegisterParams, TokenPair};

/// Maximum capacity of the refresh-token grace-period cache.
const GRACE_CAPACITY: u64 = 100_000;

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
}
