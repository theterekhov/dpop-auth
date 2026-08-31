//! Store-layer error type.

use thiserror::Error;

/// Errors raised by the PostgreSQL auth service.
///
/// The `Unauthorized` variant carries no detail: from the outside,
/// a wrong password and a missing user are indistinguishable (anti-reconnaissance).
/// The audit log (`dpop_login_attempts`) still records the real reason.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// Bad credentials or an unknown/invalid refresh token.
    #[error("invalid credentials")]
    Unauthorized,

    /// The identifier is already taken.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Self-registration is disabled by configuration.
    #[error("registration is disabled")]
    RegistrationDisabled,

    /// The input failed validation.
    #[error("validation failed: {0}")]
    Validation(String),

    /// An internal error (database, crypto).
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for ServiceError {
    fn from(value: sqlx::Error) -> Self {
        ServiceError::Internal(value.to_string())
    }
}
