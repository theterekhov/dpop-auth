//! In-memory replay-protection caches.
//!
//! - [`jti`] - access-token `jti` replay prevention.
//! - [`nonce`] - DPoP `nonce` request caching for challenges.
//! - [`totp`] - TOTP code replay prevention (`cfg(feature = "totp")`).

pub mod jti;
pub mod nonce;

#[cfg(feature = "totp")]
pub mod totp;

/// Maximum number of entries per cache.
const CACHE_CAPACITY: u64 = 100_000;
