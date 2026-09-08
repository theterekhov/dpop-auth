//! Cryptographic primitives: JWK thumbprints, token generation, and password hashing.
//!
//! - [`dpop`] - JWK thumbprint (RFC 7638), `ath` claims, and token hashing.
//! - [`entropy`] - CSPRNG refresh token secrets and identifier hashing for audit trails.
//! - [`password`] - Argon2id password hashing (`cfg(feature = "postgres")`).
//! - [`totp`] - TOTP helpers and recovery codes (`cfg(feature = "totp")`).

/// JWK thumbprints (RFC 7638), `ath` claims, and (S)SHA-256 token hashing.
pub mod dpop;
pub mod entropy;

#[cfg(feature = "postgres")]
pub mod password;

#[cfg(feature = "totp")]
pub mod totp;

pub use dpop::{compute_ath, compute_jwk_thumbprint, hash_token};
