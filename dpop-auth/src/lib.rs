#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::tabs_in_doc_comments)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! DPoP (RFC 9449) authentication for Axum
//!
//! A reusable library that validates DPoP proofs, issues and verifies
//! sender-constrained access tokens, and manages opaque refresh tokens.

pub mod cache;
pub mod config;
pub mod crypto;
pub mod dpop;
pub mod error;
pub mod token;

pub use config::{DpopConfig, TokenSigner};
pub use error::DpopError;
pub use jsonwebtoken::jwk::Jwk;
