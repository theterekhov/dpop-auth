//! TOTP-specific repository functions (feature `totp`).

use sqlx::PgConnection;
use uuid::Uuid;

/// Store a pending (draft) TOTP secret for a user.
///
/// Written only while 2FA is not yet enabled. The draft is kept separate from
/// the active `totp_secret` until the first code virifies (`active_totp`),
/// so an abandoned setup never overwrites a live secret.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn set_pending_totp_secret(
    conn: &mut PgConnection,
    user_id: Uuid,
    secret: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_users
		SET totp_pending_secret = $2,
			totp_pending_at = now()
		WHERE id = $1
			AND totp_enabled = FALSE
			AND deleted_at IS NULL
		"#,
        user_id,
        secret
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Read the pending (draft) TOTP secret, rejecting drafts older
/// than the TTL.
///
/// Returns `None` if there is no draft or it has expired;
/// tha caller must start a fresh `setup_2fa` in that case. The TTL check
/// lives here (the draft column keeps its `totp_pending_at` timestamp,
/// so the QR code cannot be confirmed once th window has passed -
/// an abandoned tab "turns into a pumpkin").
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn get_pending_totp_secret(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
     	SELECT totp_pending_secret
      	FROM dpop_users
       	WHERE id = $1
        	AND totp_enabled = FALSE
         	AND totp_pending_at > now() - INTERVAL '10 minutes'
          	AND deleted_at IS NULL
     	"#,
        user_id
    )
    .fetch_optional(conn)
    .await
    .map(Option::flatten)
}

/// Activate TOTP after a successful first-code verification.
///
/// Promotes the pending draft to the active `totp_secret`, flips
/// the flag and clears the pending columns atomically. Called inside a transaction
/// together with recovery-code issuance so that activation and recovery
/// codes commit or roll back together.
///
/// Guards (`totp_pending_secret IS NOT NULL`) so a user with no draft
/// cannot be silently enabled with a NULL secret.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn activate_totp(conn: &mut PgConnection, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_users
		SET
			totp_secret = totp_pending_secret,
			totp_enabled = TRUE,
			totp_enabled_at = now(),
			totp_pending_secret = NULL,
			totp_pending_at = NULL
		WHERE id = $1
			AND totp_pending_secret IS NOT NULL
			AND deleted_at IS NULL
		"#,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Disable TOTP authentication and purge the stored
/// (active) secret together with any leftover pending draft.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn disable_totp(conn: &mut PgConnection, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_users
		SET
			totp_secret = NULL,
			totp_enabled = FALSE,
			totp_enabled_at = NULL,
			totp_pending_secret = NULL,
			totp_pending_at = NULL
		WHERE id = $1
			AND totp_enabled = TRUE
			AND deleted_at IS NULL
		"#,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Insert recovery code hashes for a user in a simple atomic batch query.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails or a
/// constraint is violated.
pub async fn create_recovery_codes(
    conn: &mut PgConnection,
    user_id: Uuid,
    code_hashes: &[String],
) -> Result<(), sqlx::Error> {
    if code_hashes.is_empty() {
        return Ok(());
    }

    sqlx::query!(
        r#"
     	INSERT INTO dpop_recovery_codes (user_id, code_hash)
      	SELECT
       		$1,
         	unnest($2::text[])
     	"#,
        user_id,
        code_hashes
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Consume an active recovery code for a specific user via atomic CAS.
///
/// The `user_id` is part of the `WHERE` clause, ensuring that an attempt
/// to consume a code belonging to a different user is rejected **without**
/// burning it.
///
/// Returns the record ID if the code was active and successfully
/// marked as used, or `None` if it was already used, belongs to another user,
/// or does not exist.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn consume_recovery_code(
    conn: &mut PgConnection,
    user_id: Uuid,
    code_hash: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        UPDATE dpop_recovery_codes
        SET used_at = now()
        WHERE user_id = $1
        	AND code_hash = $2
         	AND used_at IS NULL
        RETURNING id
		"#,
        user_id,
        code_hash
    )
    .fetch_optional(conn)
    .await
}

/// Invalidate all active codes for a given user.
///
/// Typically called during 2FA deactivation or when
/// rotating/regenerating recovery codes.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn invalidate_recovery_codes_for_user(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_recovery_codes
		SET used_at = now()
		WHERE user_id = $1
			AND used_at IS NULL
		"#,
        user_id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Count the number of active, unconsumed recovery codes for a user.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query fails.
pub async fn count_active_recovery_codes(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
		SELECT COUNT(*) as "count!"
		FROM dpop_recovery_codes
		WHERE id = $1
			AND used_at IS NULL
		"#,
        user_id
    )
    .fetch_one(conn)
    .await
}
