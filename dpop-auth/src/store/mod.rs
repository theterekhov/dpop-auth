//! PostgreSQL store (feature `postgres`): migrations, models, repo, service.

pub mod error;
pub mod models;
pub mod pool;
pub mod repo;
pub mod service;

mod password;

pub use error::ServiceError;
pub use pool::{create_pool, run_migrations};
pub use service::{AuthService, LoginOutcome, TokenPair};
