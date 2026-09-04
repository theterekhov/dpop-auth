//! Row types mapped from the `dpop_*` tables.

use chrono::{DateTime, Utc};
use sqlx::{prelude::FromRow, types::ipnetwork::IpNetwork};
use uuid::Uuid;

/// A row representing a user in the `dpop_users` table.
#[derive(Clone, FromRow)]
pub struct UserRow {
    /// Internal primary key (time-ordered UUIDv7).
    pub id: Uuid,
    /// Publicly exposed user identifier (UUIDv4 for safe use in external APIs).
    pub public_id: Uuid,
    /// Password hash (e.g., Argon2id).
    pub password_hash: String,
    /// Display name or full name of the user.
    pub name: String,
    /// Timestamp of the last password modification (used to invalidate older sessions).
    pub password_changed_at: Option<DateTime<Utc>>,
    /// Base32-encoded or encrypted TOTP secret key for two-factor authentication.
    pub totp_secret: Option<String>,
    /// Indicates whether two-factor authentication (TOTP) is currently enabled.
    pub totp_enabled: bool,
    /// Timestamp when two-factor authentication was activated.
    pub totp_enabled_at: Option<DateTime<Utc>>,
    /// Unconfirmed Base32 TOTP secret generated during the 2FA enrollment flow.
    ///
    /// Cleared and atomically promoted to [`Self::totp_secret`] upon successful verification.
    pub totp_pending_secret: Option<String>,
    /// Timestamp when the pending TOTP setup was initiated (used to enforce enrollment TTL).
    pub totp_pending_at: Option<DateTime<Utc>>,
    /// Timestamp of the user's most recent successful login.
    pub last_login_at: Option<DateTime<Utc>>,
    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Record last update timestamp (automatically maintained via trigger).
    pub updated_at: DateTime<Utc>,
    /// Soft-delete timestamp. `None` if the account is active.
    pub deleted_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("id", &self.id)
            .field("public_id", &self.public_id)
            .field("password_hash", &"[REDACTED]")
            .field("name", &self.name)
            .field("totp_enabled", &self.totp_enabled)
            .finish()
    }
}

/// A row representing a user's login identifier in the `dpop_identifiers` table.
#[derive(Clone, FromRow)]
pub struct IdentifierRow {
    /// Internal primary key (time-ordered UUIDv7).
    pub id: Uuid,
    /// Foreign key referencing the parent user in `dpop_users(id)`.
    pub user_id: Uuid,
    /// Identifier type or scheme (e.g., `"email"`, `"phone"`, `"username"`).
    pub kind: String,
    /// Normalized identifier value (e.g., lowercase email address).
    pub value: String,
    /// Indicates if this is the primary identifier for the user and kind.
    pub is_primary: bool,
    /// Timestamp when ownership of this identifier was verified. `None` if unverified.
    pub verified_at: Option<DateTime<Utc>>,
    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Record last update timestamp (automatically maintained via trigger).
    pub updated_at: DateTime<Utc>,
    /// Soft-delete timestamp. `None` if the identifier is active.
    pub deleted_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for IdentifierRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentifierRow")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("kind", &self.kind)
            .field("value", &self.value)
            .field("is_primary", &self.is_primary)
            .field("verified_at", &self.verified_at)
            .finish()
    }
}

/// A row representing a stored refresh token in the `dpop_refresh_tokens` table.
#[derive(Clone, FromRow)]
pub struct RefreshTokenRow {
    /// Internal primary key (time-ordered UUIDv7).
    pub id: Uuid,
    /// Foreign key referencing the token owner in `dpop_users(id)`.
    pub user_id: Uuid,
    /// Cryptographic hash of the refresh token secret (e.g., SHA-256).
    pub token_hash: String,
    /// Family identifier (UUID) grouping rotated tokens for reuse detection.
    pub fam: Uuid,
    /// JWK SHA-256 thumbprint (`jkt`) binding the token to the client's public key.
    pub dpop_jkt: String,
    /// Captured `User-Agent` header value of the client at token issuance.
    pub user_agent: Option<String>,
    /// Absolute expiration timestamp after which the token is invalid.
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the token was revoked or rotated. `None` if active.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for RefreshTokenRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRow")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[REDACTED]")
            .field("fam", &self.fam)
            .field("dpop_jkt", &self.dpop_jkt)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// Parameters required to insert a new refresh token into `dpop_refresh_tokens`.
pub struct CreateRefreshTokenParams {
    /// Owner user ID.
    pub user_id: Uuid,
    /// Precomputed cryptographic hash of the raw refresh token string.
    pub token_hash: String,
    /// Refresh token family identifier for rotation tracking.
    pub fam: Uuid,
    /// DPoP public key thumbprint (`jkt`) the token is bound to.
    pub dpop_jkt: String,
    /// Client `User-Agent` string at creation time.
    pub user_agent: Option<String>,
    /// Expiration timestamp for the newly issued token.
    pub expires_at: DateTime<Utc>,
}

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
