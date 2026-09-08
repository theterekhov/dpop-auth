//! Transactional email outbox worker (feature `email` + `postgres`).

use std::{sync::Arc, time::Duration};

use chrono::Utc;

use crate::{
    EmailError,
    email::EmailSender,
    store::repo::email::{claim_pending_emails, mark_email_failed, mark_email_sent},
};

/// Default number of emails claimed per batch.
pub const DEFAULT_BATCH_SIZE: i64 = 10;

/// Base backoff (seconds) for the first retry (30s, 60s, 120s ...).
pub const BACKOFF_BASE_SECS: u64 = 30;

/// Maximum retry backoff limit (1 hour).
pub const BACKOFF_MAX_SECS: u64 = 3600;

/// Re-claim a row whose lock is older than this (crash recovery).
pub const RECLAIM_AFTER_SECS: f64 = 300.0;

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

        let mut handles = Vec::new();

        for item in batch {
            let pool = self.pool.clone();
            let sender = self.sender.clone();

            handles.push(tokio::spawn(async move {
                match sender
                    .send(&item.to_address, &item.subject, &item.body)
                    .await
                {
                    Ok(()) => {
                        if let Ok(mut conn) = pool.acquire().await {
                            let _ = mark_email_sent(&mut conn, item.id).await;
                        }
                    }
                    Err(e) => {
                        let backoff_secs = compute_backoff_secs(item.attempts);
                        let available_at = Utc::now() + chrono::Duration::seconds(backoff_secs);

                        if let Ok(mut conn) = pool.acquire().await {
                            let _ =
                                mark_email_failed(&mut conn, item.id, available_at, &e.to_string())
                                    .await;
                        }
                    }
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
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
    use std::sync::Arc;

    use chrono::DateTime;
    use sqlx::{PgConnection, PgPool};

    use crate::StubEmailSender;
    use crate::store::repo::email::enqueue_email;

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
