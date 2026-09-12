//! TOTP code replay prevention.

use std::time::Duration;

use moka::future::Cache;

use crate::cache::CACHE_CAPACITY;

/// Time-to-live of a TOTP replay entry (90s = 3 time steps).
///
/// A code is valid for at most `step * (2 * skew + 1)` seconds; keeping the entry
/// for 90s prevents replaying the code inside its whole validity window.
const TOTP_REPLAY_TTL: Duration = Duration::from_secs(90);

/// Cache of already-used TOTP codes: `(user_id, code) -> ()`.
pub type TotpReplayCache = Cache<(uuid::Uuid, String), ()>;

/// Crate a [`TotpReplayCache`] with a 90-second TTL.
pub fn create_totp_replay_cache() -> TotpReplayCache {
    Cache::builder()
        .time_to_live(TOTP_REPLAY_TTL)
        .max_capacity(CACHE_CAPACITY)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn totp_replay_cache_prevents_replay() {
        let cache = create_totp_replay_cache();
        let key = (uuid::Uuid::new_v4(), "123456".to_string());

        assert!(!cache.contains_key(&key));
        cache.insert(key.clone(), ()).await;
        assert!(cache.contains_key(&key));
    }

    #[tokio::test]
    async fn totp_key_is_user_and_code() {
        let cache = create_totp_replay_cache();
        let (user_a, user_b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());

        cache.insert((user_a, "123456".to_string()), ()).await;

        assert!(cache.contains_key(&(user_a, "123456".to_string())));
        assert!(!cache.contains_key(&(user_a, "654321".to_string())));
        assert!(!cache.contains_key(&(user_b, "123456".to_string())));
    }
}
