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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nonce_absent_then_present() {
        let cache = create_nonce_cache();
        let nonce = "nonce-1".to_string();

        assert!(!cache.contains_key(&nonce));
        cache.insert(nonce.clone(), true).await;
        assert!(cache.contains_key(&nonce));
    }

    #[tokio::test]
    async fn nonce_survives_reuse_within_window() {
        let cache = create_nonce_cache();
        let nonce = "nonce-2".to_string();

        cache.insert(nonce.clone(), true).await;
        for _ in 0..10 {
            assert!(cache.contains_key(&nonce));
        }

        cache.remove(&nonce).await;
        assert!(!cache.contains_key(&nonce));
    }
}
