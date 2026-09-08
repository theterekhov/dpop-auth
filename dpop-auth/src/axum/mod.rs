//! Axum integration: extractor, middleware layer, and cookie helpers.
//!
//! This module groups the three axum-specific layers of [`crate`]:
//!
//! - [`extractor`] - `DpopSession<T>` extractor for handlers.
//! - [`middleware`] - `DpopLayer` / `DpopService` tower middleware.
//! - [`cookie`] - refresh-token cookie helpers (`cfg(feature = "cookie")`).

pub mod extractor;
pub mod middleware;

#[cfg(feature = "cookie")]
pub mod cookie;
