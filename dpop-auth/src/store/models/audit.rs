//! `dpop_login_attempts` and `dpop_recovery_codes` row types.

use chrono::{DateTime, Utc};
use sqlx::{prelude::FromRow, types::ipnetwork::IpNetwork};
use uuid::Uuid;

/// A row representing an authentication audit entry in the `dpop_login_attempts` table.
#[derive(Clone, FromRow)]
pub struct LoginAttemptRow {
    /// Internal primary key (time-ordered UUIDv7).
    pub id: Uuid,
    /// Identifier type used during the attempt (e.g., `"email"`).
    pub identifier_kind: String,
    /// Identifier value submitted during the attempt.
    pub identifier_value: String,
    /// Originating IP address of the client (IPv4 or IPv6 with subnet mask).
    pub ip_address: IpNetwork,
    /// Outcome of the login attempt (`true` if authentication succeeded).
    pub success: bool,
    /// Explanation message or error code if the attempt failed (e.g., `"invalid_credentials"`).
    pub failure_reason: Option<String>,
    /// Timestamp when the login attempt occurred.
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for LoginAttemptRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginAttemptRow")
            .field("id", &self.id)
            .field("identifier_kind", &self.identifier_kind)
            .field("identifier_value", &self.identifier_value)
            .field("ip_address", &self.ip_address)
            .field("success", &self.success)
            .field("failure_reason", &self.failure_reason)
            .finish()
    }
}

/// A row representing a recovery code in the `dpop_recovery_codes` table.
#[cfg(feature = "totp")]
#[derive(Clone, FromRow)]
pub struct RecoveryCodeRow {
    /// Internal primary key (time-ordered UUIDv7).
    pub id: Uuid,
    /// Foreign key referencing the owner in `dpop_users(id)`.
    pub user_id: Uuid,
    /// Cryptographic hash of the recovery code (SHA-256).
    pub code_hash: String,
    /// Timestamp when the code was used. `None` if still active.
    pub used_at: Option<DateTime<Utc>>,
    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
}

#[cfg(feature = "totp")]
impl std::fmt::Debug for RecoveryCodeRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCodeRow")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_hash", &["REDACTED"])
            .field("used_at", &self.used_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}