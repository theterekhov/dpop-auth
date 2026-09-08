//! Access-token `jti` replay prevention.

use std::time::Duration;

use moka::future::Cache;

use crate::cache::CACHE_CAPACITY;

/// Cache of already-seen `jti` values (single-use proof identifiers).
pub type JtiCache = Cache<String, bool>;

/// Create a [`JtiCache`] with a dynamic TTL based on clock skew.
///
/// # Security Note
///
/// The TTL must strictly cover the maximum valid lifetime of a DPoP proof.
/// Since a proof is accepted if its `iat` is within `now +- clock_skew`,
/// the theoretical maximum lifetime of a proof is `clock_skew * 2`.
/// A small 5-second safety buffer is added to account for CPU or network latency.
pub fn create_jti_cache(ttl: Duration) -> JtiCache {
    Cache::builder()
        .time_to_live(ttl)
        .max_capacity(CACHE_CAPACITY)
        .build()
}
