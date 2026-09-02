//! Multi-tenant transaction guard (feature `postgres`).

use std::ops::{Deref, DerefMut};

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

/// The custom Grand Unified Configuration (GUC) setting that
/// stores the active tenant identifier.
///
/// PostgreSQL requires user-defined configuration parameters to contain a dot (`.`).
/// The `app.` prefix is the standard application namespace convention.
pub const TENANT_SETTING: &str = "app.current_tenant";

/// An RAII transaction guard scoped to an isolated database tenant.
///
/// [`TenantTx`] guarantees tenant data isolation at the database engine level via
/// PostgreSQL Row-Level Security (RLS).
///
/// # Security Model
///
/// Upon calling [`TenantTx::begin`], a dedicated transaction is started, and
/// `SELECT set_config('app.current_tenant', $1, true)` is executed
/// on that connection.
///
/// * **Transactional scope (`is_local = true`):** Equivalent to `SET LOCAL`,
///   the parameter exists strictly for the lifetime of this transaction. Once
///   committed, rolled back, or dropped, the setting is discarded by PostgreSQL,
///   preventing session state leakage across pooled connections.
/// * **Transparent repository interop:** [`TenantTx`] implements [`Deref`]
///   and [`DerefMut`] targeting [`sqlx::PgConnection`], allowing repository functions
///   accepting `&mut PgConnection` to receive `&mut tx` directly.
/// * **Automatic rollback (RAII):** Dropping a [`TenantTx`]
///   without calling [`TenantTx::commit`] automatically initiates an
///   asynchronous rollback in the underlying [`Transaction`].
///
/// # Examples
///
/// ```no_run
/// use sqlx::PgPool;
/// use uuid::Uuid;
/// use dpop_auth::store::TenantTx;
///
/// async fn example(pool: &PgPool, tenant_id: Uuid) -> Result<(), sqlx::Error> {
/// 	let mut tx = TenantTx::begin(pool, tenant_id).await?;
///
/// 	// RLS policies automatically filter rows matching `app.current_tenant`
/// 	sqlx::query("SELECT * FROM tickets")
/// 		.fetch_all(&mut *tx)
/// 		.await?;
///
/// 	tx.commit().await?;
///
/// 	Ok(())
/// }
///
/// ```
pub struct TenantTx {
    tx: Transaction<'static, Postgres>,
    tenant_id: Uuid,
}

impl TenantTx {
    /// Begins a new transaction scoped to the specified `tenant_id`.
    ///
    /// Sets the local GUC setting `app.current_tenant` to
    /// `tenant_id` within the newly opened transaction.
    ///
    /// # Errors
    ///
    /// Returns [`sqlx::Error`] if the connection cannot be acquired,
    /// `BEGIN` fails, or executing `set_config` encounters a database error.
    pub async fn begin(pool: &PgPool, tenant_id: Uuid) -> Result<Self, sqlx::Error> {
        let mut tx = pool.begin().await?;

        // `SET` is a utility statement and does not accept bind parameters
        // in the extended query protocol. We invoke `set_config(..., is_local = true)`
        // instead.
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;

        Ok(Self { tx, tenant_id })
    }

    /// Returns the [`Uuid`] of the tenant bound to this transaction.
    #[must_use]
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Commits the underlying transaction, persisting all changes
    /// and resetting tenant context.
    ///
    /// # Errors
    ///
    /// Returns [`sqlx::Error`] if the commit fails or constraint verification fails.
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    /// Explicitly rolls back the transaction, discarding all uncommitted changes.
    ///
    /// Note that dropping `TenantTx` without calling [`Self::commit`]
    /// will also trigger a rollback automatically.
    ///
    /// # Errors
    ///
    /// Returns [`sqlx::Error`] if the rollback command fails.
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}

impl Deref for TenantTx {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for TenantTx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create the demo tables (no RLS yet) and seed two tenants with one
    /// ticket each. Returns the two tenant ids.
    async fn setup_demo(pool: &PgPool) -> (Uuid, Uuid) {
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();

        sqlx::query("DROP TABLE IF EXISTS demo_tickets")
            .execute(pool)
            .await
            .unwrap();

        sqlx::query("DROP TABLE IF EXISTS demo_tenants")
            .execute(pool)
            .await
            .unwrap();

        sqlx::query(
            r#"
         	CREATE TABLE demo_tenants (
          		id UUID PRIMARY KEY,
            	name TEXT NOT NULL
          	)
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	CREATE TABLE demo_tickets (
          		id UUID PRIMARY KEY,
            	tenant_id UUID NOT NULL REFERENCES demo_tenants(id),
             	title TEXT NOT NULL,
              	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
          	)
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	INSERT INTO demo_tenants (id, name)
          	VALUES
           		($1, 'Tenant A'),
             	($2, 'Tenant B')
         	"#,
        )
        .bind(tenant_a)
        .bind(tenant_b)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	INSERT INTO demo_tickets (id, tenant_id, title)
          	VALUES ($1, $2, 'A ticket')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	INSERT INTO demo_tickets (id, tenant_id, title)
          	VALUES ($1, $2, 'B ticket')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_b)
        .execute(pool)
        .await
        .unwrap();

        (tenant_a, tenant_b)
    }

    /// Enable RLS on the demo tables and create the isolation policy.
    /// Creates a non-superuser role `dpop_app` that the isolation tests
    /// assume via `SET LOCAL ROLE`, so RLS genuinely filters.
    async fn enable_rls(pool: &PgPool) {
        sqlx::query(
            r#"
            DO $$ BEGIN
            	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dpop_app')
             		THEN CREATE ROLE dpop_app;
               	END IF;
            END $$
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	GRANT SELECT, INSERT, UPDATE, DELETE
          		ON demo_tenants, demo_tickets TO dpop_app
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	ALTER TABLE demo_tickets ENABLE ROW LEVEL SECURITY
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	ALTER TABLE demo_tickets FORCE ROW LEVEL SECURITY
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	DROP POLICY IF EXISTS tenant_isolation ON demo_tickets
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
         	CREATE POLICY tenant_isolation ON demo_tickets
          		USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::uuid)
            	WITH CHECK
             		(tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::uuid)
         	"#,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    // TenantTx mechanics

    #[sqlx::test]
    async fn begin_sets_local_tenant(pool: PgPool) {
        let tenant_id = Uuid::new_v4();
        let mut tx = TenantTx::begin(&pool, tenant_id).await.unwrap();

        let value: Option<String> = sqlx::query_scalar(
            r#"
         	SELECT current_setting('app.current_tenant', TRUE)
         	"#,
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();

        assert_eq!(value.as_deref(), Some(tenant_id.to_string().as_str()));
    }

    #[sqlx::test]
    async fn tenant_id_accessor_returns_id(pool: PgPool) {
        let tenant_id = Uuid::new_v4();
        let tx = TenantTx::begin(&pool, tenant_id).await.unwrap();

        assert_eq!(tx.tenant_id, tenant_id);
    }

    #[sqlx::test]
    async fn commit_persists_writes(pool: PgPool) {
        let (tenant_a, _) = setup_demo(&pool).await;

        let mut tx = TenantTx::begin(&pool, tenant_a).await.unwrap();
        sqlx::query(
            r#"
            INSERT INTO demo_tickets (id, tenant_id, title)
            VALUES ($1, $2, 'committed')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *tx)
        .await
        .unwrap();

        tx.commit().await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            r#"
         	SELECT COUNT(*) FROM demo_tickets
          	WHERE title = 'committed'
         	"#,
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test]
    async fn rollback_discards_writes(pool: PgPool) {
        let (tenant_a, _) = setup_demo(&pool).await;

        let mut tx = TenantTx::begin(&pool, tenant_a).await.unwrap();
        sqlx::query(
            r#"
            INSERT INTO demo_tickets (id, tenant_id, title)
            VALUES ($1, $2, 'discarded')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *tx)
        .await
        .unwrap();

        tx.rollback().await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            r#"
         	SELECT COUNT(*) FROM demo_tickets
          	WHERE title = 'discarded'
         	"#,
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn drop_without_commit_rolls_back(pool: PgPool) {
        let (tenant_a, _) = setup_demo(&pool).await;

        {
            let mut tx = TenantTx::begin(&pool, tenant_a).await.unwrap();
            sqlx::query(
                r#"
            INSERT INTO demo_tickets (id, tenant_id, title)
            VALUES ($1, $2, 'dropped')
         	"#,
            )
            .bind(Uuid::new_v4())
            .bind(tenant_a)
            .execute(&mut *tx)
            .await
            .unwrap();

            // `tx` drops here without commit -> automatic rollback
        }

        let mut conn = pool.acquire().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            r#"
         	SELECT COUNT(*) FROM demo_tickets
          	WHERE title = 'dropped'
         	"#,
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn session_update_does_not_leak(pool: PgPool) {
        let tenant_id = Uuid::new_v4();
        let tx = TenantTx::begin(&pool, tenant_id).await.unwrap();
        tx.commit().await.unwrap();

        // A fresh connection must not carry the previous tenant.
        let mut conn = pool.acquire().await.unwrap();
        let value: Option<String> = sqlx::query_scalar(
            r#"
         	SELECT current_setting('app.current_tenant', TRUE)
         	"#,
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();

        assert!(value.is_none());
    }

    // RlS isolation (as the non-superuser `dpop_app` role)

    #[sqlx::test]
    async fn rls_hides_other_tenants_rows(pool: PgPool) {
        let (tenant_a, tenant_b) = setup_demo(&pool).await;
        enable_rls(&pool).await;

        // Tenant A sees only its own ticket.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE dpop_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant_a.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();

        let titles: Vec<String> = sqlx::query_scalar(
            r#"
         	SELECT title FROM demo_tickets
          	ORDER BY title
         	"#,
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(titles, vec!["A ticket".to_string()]);
        tx.rollback().await.unwrap();

        // Tenant B sees only its own ticket.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE dpop_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant_b.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();

        let titles: Vec<String> = sqlx::query_scalar(
            r#"
         	SELECT title FROM demo_tickets
          	ORDER BY title
         	"#,
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert_eq!(titles, vec!["B ticket".to_string()]);
    }

    #[sqlx::test]
    async fn rls_without_context_sees_nothing(pool: PgPool) {
        setup_demo(&pool).await;
        enable_rls(&pool).await;

        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE dpop_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        // no SET LOCAL app.current_tenant -> default deny

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM demo_tickets")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn rls_blocks_cross_tenant_insert(pool: PgPool) {
        let (tenant_a, tenant_b) = setup_demo(&pool).await;
        enable_rls(&pool).await;

        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE dpop_app")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant_a.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();

        sqlx::query("SAVEPOINT sp").execute(&mut *tx).await.unwrap();

        let smuggled = sqlx::query(
            r#"
         	INSERT INTO demo_tickets (id, tenant_id, title)
          	VALUES ($1, $2, 'smuggled')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_b)
        .execute(&mut *tx)
        .await;
        assert!(smuggled.is_err());

        sqlx::query("ROLLBACK TO SAVEPOINT sp")
            .execute(&mut *tx)
            .await
            .unwrap();

        let own = sqlx::query(
            r#"
         	INSERT INTO demo_tickets (id, tenant_id, title)
          	VALUES ($1, $2, 'ok')
         	"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a)
        .execute(&mut *tx)
        .await;
        assert!(own.is_ok());
    }
}
