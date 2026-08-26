//! In-memory replay-protection caches.

use std::time::Duration;

use moka::future::Cache;

/// Time-to-live of a `jti` entry.
///
/// Must be greater than or equal to the proof freshness window
/// (`clock_skew`, default 60s). Keeping entries for 60s guarantees that
/// an attacker cannot replay an intercepted proof:
/// - Within 60s: rejected by `JtiCache`.
/// - After 60s: rejected by `claims.iat` freshness window check (`DpopError::Expired`).
const JTI_TTL: Duration = Duration::from_secs(60);

/// Time-to-live of a server-issued nonce entry (300s / 5 minutes).
///
/// Long enough to tolerate mobile latency and request retries.
/// Multi-use is a permitted within this window per RFC 9449 section 11.1
/// since `jti` tracking prevents proof replay.
const NONCE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of entries per cache.
const CACHE_CAPACITY: u64 = 100_000;

/// Cache of already-seen `jti` values (single-use proof identifiers).
pub type JtiCache = Cache<String, bool>;

/// Cache of nonces issued by this server.
pub type NonceCache = Cache<String, bool>;

/// Create a [`JtiCache`] with a 60-second TTL.
pub fn create_jti_cache() -> JtiCache {
    Cache::builder()
        .time_to_live(JTI_TTL)
        .max_capacity(CACHE_CAPACITY)
        .build()
}

/// Create a [`NonceCache`] with a 300-second TTL.
pub fn create_nonce_cache() -> NonceCache {
    Cache::builder()
        .time_to_live(NONCE_TTL)
        .max_capacity(CACHE_CAPACITY)
        .build()
}
