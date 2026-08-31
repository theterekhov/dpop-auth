//! Argon2id password hashing (feature `postgres`).

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::phc::SaltString,
};

use crate::store::error::ServiceError;

/// Hash a password with Argon2id and a fresh random salt.
///
/// The returned value is a PHC string (`$argon2id$v=19$m=...,t=...,p=...$...`)
/// that embeds the salt and parameters.
pub fn hash_password(password: &str) -> Result<String, ServiceError> {
    let salt = SaltString::generate();

    Argon2::default()
        .hash_password_with_salt(password.as_bytes(), salt.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| ServiceError::Internal(e.to_string()))
}

/// Async wrapper: hash a password off the async runtime (CPU-bound).
pub async fn hash_password_async(password: String) -> Result<String, ServiceError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
}

/// Verify a password against a PHC string, in constant time.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ServiceError> {
    let parsed = PasswordHash::new(hash).map_err(|e| ServiceError::Internal(e.to_string()))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Async wrapper: verify a password off the async runtime (CPU-bound).
pub async fn verify_password_async(password: String, hash: String) -> Result<bool, ServiceError> {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
}
