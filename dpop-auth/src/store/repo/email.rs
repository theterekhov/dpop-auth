//! Transactional email outbox queries (feature `email`).

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, prelude::FromRow};
use uuid::Uuid;

/// A row of the `dpop_email_outbox`.
#[derive(Debug, Clone, FromRow)]
pub struct OutboxEmailRow {
    /// Internal primary key.
    pub id: Uuid,
    /// Recipient address.
    pub to_address: String,
    /// Email subject.
    pub subject: String,
    /// Email plain-text body.
    pub body: String,
    /// Delivery attempts so far.
    pub attempts: i16,
    /// Maximum delivery attempts before giving up.
    pub max_attempts: i16,
}

/// Enqueues an outgoing email into the transactional outbox table.
///
/// Call this inside the same database transaction as the business operation.
/// This guarantees that state changes and the email dispatch commit atomically,
/// preventing ghost emails or missed notifications if a failure occurs.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if inserting the row into `dpop_email_outbox` fails.
pub async fn enqueue_email(
    conn: &mut PgConnection,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		INSERT INTO dpop_email_outbox (to_address, subject, body)
		VALUES ($1, $2, $3)
		"#,
        to,
        subject,
        body
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Atomically claims up to `batch_size` pending emails for delivery.
///
/// Utilizes PostgreSQL's `FOR UPDATE SKIP LOCKED` clause to allow multiple worker
/// instances to poll the same queue concurrently without blocking or deadlocks.
///
/// # Crash Recovery
///
/// If a previously claiming worker crashed before calling [`mark_email_sent`] or
/// [`mark_email_failed`], the row's `locked_at` timestamp will remain set.
/// Rows with `locked_at` older than `reclaim_after_secs` are considered abandoned
/// and will be reclaimed by this query.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the underlying query fails or the connection is dropped.
pub async fn claim_pending_emails(
    conn: &mut PgConnection,
    batch_size: i64,
    reclaim_after_secs: f64,
) -> Result<Vec<OutboxEmailRow>, sqlx::Error> {
    sqlx::query_as!(
        OutboxEmailRow,
        r#"
		UPDATE dpop_email_outbox
		SET locked_at = now()
		WHERE id IN (
			SELECT id FROM dpop_email_outbox
			WHERE sent_at IS NULL
				AND (
				locked_at IS NULL
					OR locked_at < now() - make_interval(secs => $2::double precision)
				)
				AND available_at <= now()
				AND attempts < max_attempts
			ORDER BY created_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING
			id,
			to_address,
			subject,
			body,
			attempts,
			max_attempts
		"#,
        batch_size,
        reclaim_after_secs
    )
    .fetch_all(conn)
    .await
}

/// Marks an email as successfully delivered.
///
/// Sets `sent_at = now()` and resets `locked_at = NULL`,
/// permanently retiring the row from future worker claims.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database update fails.
pub async fn mark_email_sent(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_email_outbox
		SET
			sent_at = now(),
			locked_at = NULL
		WHERE id = $1
		"#,
        id
    )
    .execute(conn)
    .await
    .map(|_| ())
}

/// Marks an email delivery attempts as failed and schedules a retry.
///
/// Increments the `attempts` counter, stores `last_error`, unlocks the row by
/// resetting `locked_at = NULL`, and sets `available_at` to the next retry time.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database update fails.
pub async fn mark_email_failed(
    conn: &mut PgConnection,
    id: Uuid,
    available_at: DateTime<Utc>,
    error: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
		UPDATE dpop_email_outbox
		SET
			attempts = attempts + 1,
			last_error = $2,
			available_at = $3,
			locked_at = NULL
		WHERE id = $1
		"#,
        id,
        error,
        available_at
    )
    .execute(conn)
    .await
    .map(|_| ())
}
