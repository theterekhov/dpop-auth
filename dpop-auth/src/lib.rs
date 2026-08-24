#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! DPoP (RFC 9449) authentication for Axum
//!
//! A reusable library that validates DPoP proofs, issues and verifies
//! sender-constrained access tokens, and manages opaque refresh tokens.

pub mod crypto;
pub mod error;

pub use error::DpopError;
