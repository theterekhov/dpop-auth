//! Connection pool and migrations.

use sqlx::{PgPool, postgres::PgPoolOptions};

const MAX_CONNTECTIONS: u32 = 10;

/// Create a PostgreSQL connection pool.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(MAX_CONNTECTIONS)
        .connect(database_url)
        .await
}

/// Run the embedded migrations against the pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
