//! PostgreSQL store (feature `postgres`): migrations, models, repo.

pub mod models;
pub mod pool;
pub mod repo;

pub use pool::{create_pool, run_migrations};
