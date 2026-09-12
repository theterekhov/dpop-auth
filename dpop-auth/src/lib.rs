#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::tabs_in_doc_comments)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! DPoP (RFC 9449) authentication for Axum
//!
//! A reusable library that validates DPoP proofs, issues and verifies
//! sender-constrained access tokens, and manages opaque refresh tokens.

#[doc(hidden)]
extern crate self as dpop_auth;

pub mod axum;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod dpop;
pub mod error;
pub mod state;
pub mod token;

#[cfg_attr(docsrs, doc(cfg(feature = "email")))]
#[cfg(feature = "email")]
pub mod email;

#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
#[cfg(feature = "postgres")]
pub mod service;

#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
#[cfg(feature = "postgres")]
pub mod store;

pub use axum::extractor::{DpopSession, FromExtra};
pub use axum::middleware::DpopLayer;
pub use config::{DpopConfig, TokenSigner};
pub use error::DpopError;
pub use jsonwebtoken::jwk::Jwk;
pub use state::DpopState;

#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
#[cfg(feature = "postgres")]
pub use service::{AuthService, LoginOutcome, RegisterParams, TokenPair};

#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
#[cfg(feature = "postgres")]
pub use store::{TenantTx, create_pool, run_migrations};

#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
#[cfg(feature = "postgres")]
pub use store::error::ServiceError;

#[cfg_attr(docsrs, doc(cfg(feature = "totp")))]
#[cfg(feature = "totp")]
pub use crypto::totp::TotpSetup;

#[cfg_attr(docsrs, doc(cfg(feature = "email")))]
#[cfg(feature = "email")]
pub use email::{
    EmailError, EmailSender, LogEmailSender, SmtpConfig, SmtpEmailSender, StubEmailSender,
};

#[cfg_attr(docsrs, doc(cfg(all(feature = "email", feature = "postgres"))))]
#[cfg(all(feature = "email", feature = "postgres"))]
pub use service::email::EmailOutboxWorker;

#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
#[cfg(feature = "derive")]
pub use dpop_auth_macros::FromExtra;
