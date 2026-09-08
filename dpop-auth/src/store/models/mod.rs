//! Row types mapped from the `dpop_*` database tables.
//!
//! Each struct derives [`sqlx::FromRow`] and maps 1:1 to a table.
//! Sensitive fields (`password_hash`, `token_hash`, `code_hash`)
//! have custom [`Debug`] implementations that print `[REDACTED]`.

pub mod audit;
pub mod refresh_token;
pub mod user;

pub use audit::LoginAttemptRow;

#[cfg(feature = "totp")]
pub use audit::RecoveryCodeRow;

pub use refresh_token::{CreateRefreshTokenParams, RefreshTokenRow};

pub use user::{IdentifierRow, UserRow};
