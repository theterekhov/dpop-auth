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
