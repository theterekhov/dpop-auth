//! PostgreSQL store (feature `postgres`): migrations, models, repo, tenant.

pub mod error;
pub mod models;
pub mod pool;
pub mod repo;
pub mod tenant;

pub use error::ServiceError;
pub use pool::{create_pool, run_migrations};
pub use tenant::TenantTx;