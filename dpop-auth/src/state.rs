//! Shared application state for the middleware and extractors.

use axum::extract::FromRef;

use crate::{
    DpopConfig,
    cache::{JtiCache, NonceCache, create_jti_cache, create_nonce_cache},
};

/// Shared state held by the DPoP layer and available to handlers.
#[derive(Clone)]
pub struct DpopState {
    /// Library configuration (public URL, signer, TTLs, policies).
    pub config: DpopConfig,
    /// Cache of seen proof `jti` values.
    pub jti_cache: JtiCache,
    /// Cache of nonces issued by this server.
    pub nonce_cache: NonceCache,
}

impl DpopState {
    /// Create the state and its caches from a configuration.
    pub fn new(config: DpopConfig) -> Self {
        Self {
            config,
            jti_cache: create_jti_cache(),
            nonce_cache: create_nonce_cache(),
        }
    }
}

impl FromRef<DpopState> for DpopConfig {
    fn from_ref(state: &DpopState) -> Self {
        state.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::TokenSigner;

    use super::*;

    fn test_config() -> DpopConfig {
        DpopConfig::builder()
            .public_url("https://example.com")
            .issuer("https://example.com")
            .audience("https://example.com")
            .signer(TokenSigner::symmetric(b"test-secret-key"))
            .nonce_required(true)
            .build()
            .unwrap()
    }

    #[test]
    fn state_initialization() {
        let config = test_config();
        let state = DpopState::new(config.clone());

        assert_eq!(state.config.public_url, "https://example.com");
        assert_eq!(state.config.issuer, "https://example.com");
        assert_eq!(state.config.audience, "https://example.com");
        assert!(state.config.nonce_required);

        assert_eq!(state.jti_cache.entry_count(), 0);
        assert_eq!(state.nonce_cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn state_clone_shares_underlying_caches() {
        let state = DpopState::new(test_config());
        let cloned_state = state.clone();

        state.jti_cache.insert("test-jti-1".to_string(), true).await;
        state
            .nonce_cache
            .insert("test-nonce-1".to_string(), true)
            .await;

        assert!(cloned_state.jti_cache.get("test-jti-1").await.is_some());
        assert!(cloned_state.nonce_cache.get("test-nonce-1").await.is_some());
    }

    #[tokio::test]
    async fn from_ref_extracts_config_correctly() {
        let original_config = test_config();
        let state = DpopState::new(original_config.clone());

        let extracted_config = DpopConfig::from_ref(&state);

        assert_eq!(extracted_config.public_url, original_config.public_url);
        assert_eq!(extracted_config.issuer, original_config.issuer);
        assert_eq!(extracted_config.audience, original_config.audience);
        assert_eq!(
            extracted_config.nonce_required,
            original_config.nonce_required
        );
    }
}
