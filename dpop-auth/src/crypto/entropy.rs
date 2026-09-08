//! Opaque token entropy generation and identifier hashing.
//!
//! Pure crypto helpers that must stay feature-independent: they are used by
//! the PostgreSQL `AuthService` (refresh-secret entropy) and every audit span
//! (`identifier_hash`), so they cannot depend on the `postgres` feature.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::DpopError;

use super::hash_token;

/// Refresh-secret length in bytes (256 bits of entropy).
const REFRESH_SECRET_LEN: usize = 32;

/// Computes a normalized SHA-256 hash of the identifier for audit spans.
///
/// Combines `kind` and `value` (both lowercased, separated by `:`) prior to
/// hashing via [`hash_token`]. This prevents cross-kind identifier collisions
/// while avoiding the leakage of raw Personally Identifiable Information (PII)
/// into telemetry and structured logs.
#[must_use]
pub fn identifier_hash(kind: &str, value: &str) -> String {
    let combined = format!("{}:{}", kind.to_lowercase(), value.to_lowercase());
    hash_token(combined.as_bytes())
}

/// Generates a cryptographically secure refresh token secret.
///
/// Produces 32 random bytes from the OS CSPRNG encoded as unpadded Base64URL
/// (43 characters, 256 bits of entropy).
///
/// # Errors
///
/// Returns [`DpopError::Internal`] if the underlying operating system entropy
/// source fails via `getrandom::fill`.
pub fn new_refresh_secret() -> Result<String, DpopError> {
    let mut bytes = [0_u8; REFRESH_SECRET_LEN];
    getrandom::fill(&mut bytes).map_err(|e| DpopError::Internal(e.to_string()))?;

    Ok(Base64UrlUnpadded::encode_string(&bytes))
}
