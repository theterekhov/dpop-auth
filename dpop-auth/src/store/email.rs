//! Transactional email outbox (feature `email` + `postgres`).

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, prelude::FromRow};
use uuid::Uuid;

use crate::email::{EmailError, EmailSender};

/// Default number of emails claimed per batch.
pub const DEFAULT_BATCH_SIZE: i64 = 10;

/// Base backoff (seconds) for the first retry (30s, 60s, 120s ...).
pub const BACKOFF_BASE_SECS: u64 = 30;

/// Maximum retry backoff limit (1 hour).
pub const BACKOFF_MAX_SECS: u64 = 3600;

/// Re-claim a row whose lock is older than this (crash recovery).
pub const RECLAIM_AFTER_SECS: f64 = 300.0;

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

/// Computes exponential backoff in seconds, safely saturated to avoid overflow.
///
/// The formula is `min(BACKOFF_BASE_SECS * 2^attempts, BACKOFF_MAX_SECS)`.
fn compute_backoff_secs(attempts: i16) -> i64 {
    let shift = attempts.clamp(0, 16) as u32;
    let factor = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    let backoff = BACKOFF_BASE_SECS.saturating_mul(factor);
    backoff.min(BACKOFF_MAX_SECS) as i64
}

/// Background worker that periodically polls and delivers queued emails
/// from the outbox table.
pub struct EmailOutboxWorker {
    pool: sqlx::PgPool,
    sender: Arc<dyn EmailSender>,
    batch_size: i64,
    reclaim_after_secs: f64,
}

impl EmailOutboxWorker {
    /// Creates a new worker instance with default batch size and reclaim thresholds.
    pub fn new(pool: sqlx::PgPool, sender: Arc<dyn EmailSender>) -> Self {
        Self {
            pool,
            sender,
            batch_size: DEFAULT_BATCH_SIZE,
            reclaim_after_secs: RECLAIM_AFTER_SECS,
        }
    }

    /// Sets the maximum number of email claimed per processing iteration.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Sets the lock timeout (in seconds) after which an uncompleted
    /// email is reclaimed.
    pub fn with_reclaim_after_secs(mut self, reclaim_after_secs: f64) -> Self {
        self.reclaim_after_secs = reclaim_after_secs;
        self
    }

    /// Claims a single batch of emails and attempts delivery for each
    /// item sequentially.
    ///
    /// * Successful deliveries update `sent_at` and unlock the row.
    /// * Failed deliveries compute an exponential backoff delay and
    ///   reschedule `available_at`.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError`] if acquiring a pool connection or executing database
    /// operations fails.
    pub async fn process_batch(&self) -> Result<(), EmailError> {
        let batch = {
            let mut conn = self.pool.acquire().await?;
            claim_pending_emails(&mut conn, self.batch_size, self.reclaim_after_secs).await?
        };

        for item in batch {
            match self
                .sender
                .send(&item.to_address, &item.subject, &item.body)
                .await
            {
                Ok(()) => {
                    let mut conn = self.pool.acquire().await?;
                    mark_email_sent(&mut conn, item.id).await?;
                }
                Err(e) => {
                    let backoff_secs = compute_backoff_secs(item.attempts);
                    let available_at = Utc::now() + chrono::Duration::seconds(backoff_secs);

                    let mut conn = self.pool.acquire().await?;
                    mark_email_failed(&mut conn, item.id, available_at, &e.to_string()).await?;
                }
            }
        }

        Ok(())
    }

    /// Spawns the worker polling loop onto the Tokio runtime.
    ///
    /// The worker ticks every 2 seconds. Transient batch processing
    /// errors are logged via `tracing::error!` without terminating the
    /// background loop.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.tick().await;

            loop {
                interval.tick().await;

                if let Err(e) = self.process_batch().await {
                    tracing::error!(
                        error = %e,
                        "email outbox batch processing encountered an error"
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use crate::StubEmailSender;

    use super::*;

    struct FailingSender;

    impl EmailSender for FailingSender {
        fn send<'a>(
            &'a self,
            _to: &'a str,
            _subject: &'a str,
            _body: &'a str,
        ) -> crate::email::BoxFuture<'a, Result<(), EmailError>> {
            Box::pin(std::future::ready(Err(EmailError::Send(
                "smtp down".into(),
            ))))
        }
    }

    #[derive(sqlx::FromRow)]
    struct OutboxInspect {
        attempts: i16,
        available_at: DateTime<Utc>,
        locked_at: Option<DateTime<Utc>>,
        sent_at: Option<DateTime<Utc>>,
        last_error: Option<String>,
    }

    async fn inspect(conn: &mut PgConnection) -> OutboxInspect {
        sqlx::query_as(
            r#"
       		SELECT
         		attempts,
           		available_at,
             	locked_at,
              	sent_at,
               	last_error
            FROM dpop_email_outbox
       		"#,
        )
        .fetch_one(conn)
        .await
        .unwrap()
    }

    #[sqlx::test]
    async fn enqueue_email_persists_row(pool: PgPool) {
        let stub = Arc::new(StubEmailSender::default());
        let worker = EmailOutboxWorker::new(pool.clone(), stub.clone());

        let mut conn = pool.acquire().await.unwrap();
        enqueue_email(&mut conn, "john@example.com", "Hello", "Body")
            .await
            .unwrap();

        drop(conn);

        worker.process_batch().await.unwrap();

        assert_eq!(stub.messages().len(), 1);
        assert_eq!(stub.messages()[0].to, "john@example.com");

        let mut conn = pool.acquire().await.unwrap();
        let row = inspect(&mut conn).await;
        assert!(row.sent_at.is_some());
        assert!(row.locked_at.is_none());
    }

    #[sqlx::test]
    async fn worker_failure_backs_off(pool: PgPool) {
        let worker = EmailOutboxWorker::new(pool.clone(), Arc::new(FailingSender));

        let mut conn = pool.acquire().await.unwrap();
        enqueue_email(&mut conn, "a@b.c", "Subject", "Body")
            .await
            .unwrap();

        drop(conn);

        worker.process_batch().await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let row = inspect(&mut conn).await;
        assert_eq!(row.attempts, 1);
        assert!(row.sent_at.is_none());
        assert!(row.locked_at.is_none());
        assert!(row.last_error.is_some());
        assert!(row.available_at > Utc::now(), "next retry is in the future");
    }

    #[sqlx::test]
    async fn worker_skips_not_available(pool: PgPool) {
        let worker = EmailOutboxWorker::new(pool.clone(), Arc::new(FailingSender));

        let mut conn = pool.acquire().await.unwrap();
        enqueue_email(&mut conn, "a@b.c", "Subject", "Body")
            .await
            .unwrap();

        drop(conn);

        worker.process_batch().await.unwrap();
        // The email is now backed off; a second pass must not touch it
        worker.process_batch().await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let row = inspect(&mut conn).await;
        assert_eq!(row.attempts, 1, "backoff must prevent immediate re-claim");
    }

    #[sqlx::test]
    async fn worker_respects_max_attempts(pool: PgPool) {
        let worker = EmailOutboxWorker::new(pool.clone(), Arc::new(FailingSender));

        let mut conn = pool.acquire().await.unwrap();
        sqlx::query(
            r#"
         	INSERT INTO dpop_email_outbox (
          		to_address,
            	subject,
             	body,
              	max_attempts
          	)
           	VALUES ($1, $2, $3, $4)
          	"#,
        )
        .bind("a@b.c")
        .bind("Subject")
        .bind("Body")
        .bind(1_i16)
        .execute(&mut *conn)
        .await
        .unwrap();

        drop(conn);

        worker.process_batch().await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let row = inspect(&mut conn).await;
        assert_eq!(row.attempts, 1, "attempts reaches max_attempts");
        assert!(row.sent_at.is_none());
    }

    #[sqlx::test]
    async fn worker_reclaims_stale_lock(pool: PgPool) {
        let stub = Arc::new(StubEmailSender::default());
        let worker = EmailOutboxWorker::new(pool.clone(), stub.clone());

        // Simulate a crashed worker: locked_at is 10 minutes ago, sent_at IS NULL
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query(
            r#"
         	INSERT INTO dpop_email_outbox (
          		to_address,
            	subject,
             	body,
              	locked_at
          	)
           	VALUES ($1, $2, $3, now() - INTERVAL '10 minutes')
         	"#,
        )
        .bind("crashed@example.com")
        .bind("Orphaned Subject")
        .bind("Orphaned Body")
        .execute(&mut *conn)
        .await
        .unwrap();

        drop(conn);

        // Current worker process should re-claim and send the abandoned email
        worker.process_batch().await.unwrap();

        assert_eq!(stub.messages().len(), 1);
        assert_eq!(stub.messages()[0].to, "crashed@example.com");

        let mut conn = pool.acquire().await.unwrap();
        let row = inspect(&mut conn).await;
        assert!(row.sent_at.is_some());
        assert!(row.locked_at.is_none());
    }
}
