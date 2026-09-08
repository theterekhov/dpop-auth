//! Data-access layer over `PgConnection`, split by aggregate:
//! users, identifiers, refresh tokens, login attempts, TOTP, email outbox.

pub mod identifiers;
pub mod login_attempts;
pub mod refresh_tokens;
pub mod users;

#[cfg(feature = "totp")]
pub mod totp;

#[cfg(feature = "email")]
pub mod email;
