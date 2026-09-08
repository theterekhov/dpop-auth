//! DPoP `nonce` caching for challenges.

use std::time::Duration;

use moka::future::Cache;

use crate::cache::CACHE_CAPACITY;

/// Time-to-live of a server-issued nonce entry (300s / 5 minutes).
///
/// Long enough to tolerate mobile latency and request retries.
/// Multi-use is a permitted within this window per RFC 9449 section 11.1
/// since `jti` tracking prevents proof replay.
const NONCE_TTL: Duration = Duration::from_secs(300);

/// Cache of nonces issued by this server.
pub type NonceCache = Cache<String, bool>;

/// Create a [`NonceCache`] with a 300-second TTL.
pub fn create_nonce_cache() -> NonceCache {
    Cache::builder()
        .time_to_live(NONCE_TTL)
        .max_capacity(CACHE_CAPACITY)
        .build()
}
