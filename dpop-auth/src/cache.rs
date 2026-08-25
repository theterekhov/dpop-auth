//! In-memory replay-protection caches.

use std::time::Duration;

use moka::future::Cache;

/// Time-to-live of a `jti` entry: equal to the proof freshness window.
const JTI_TTL: Duration = Duration::from_secs(60);
/// Time-to-live of a nonce entry: long enough for a client round-trip.
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
