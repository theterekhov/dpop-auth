//! `dpop_refresh_tokens` row type and its insert parameters.

use chrono::{DateTime, Utc};
use sqlx::prelude::FromRow;
use uuid::Uuid;

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