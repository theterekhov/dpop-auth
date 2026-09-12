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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::task::JoinSet;

    use super::*;

    #[tokio::test]
    async fn jti_absent_then_present() {
        let cache = create_jti_cache(Duration::from_secs(300));
        let jti = "proof-1".to_string();

        assert!(!cache.contains_key(&jti));
        cache.insert(jti.clone(), true).await;
        assert!(cache.contains_key(&jti));
    }

    #[tokio::test]
    async fn jti_second_use_is_replay() {
        let cache = create_jti_cache(Duration::from_secs(300));
        let jti = "proof-2".to_string();

        assert!(cache.entry(jti.clone()).or_insert(true).await.is_fresh());
        assert!(!cache.entry(jti.clone()).or_insert(true).await.is_fresh());
    }

    #[tokio::test]
    async fn jti_concurrent_unique_all_fresh() {
        let cache = Arc::new(create_jti_cache(Duration::from_secs(300)));
        let mut set = JoinSet::new();

        for i in 0..100 {
            let c = cache.clone();
            set.spawn(async move {
                c.entry(format!("proof-{i}"))
                    .or_insert(true)
                    .await
                    .is_fresh()
            });
        }

        let mut fresh = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                fresh += 1;
            }
        }
        assert_eq!(fresh, 100);
    }
}
