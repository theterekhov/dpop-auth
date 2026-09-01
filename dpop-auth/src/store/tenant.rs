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
