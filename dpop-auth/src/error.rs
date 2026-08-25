//! Error types for DPoP proof validation and token handling.

use thiserror::Error;

/// Errors raised while validating a DPoP proof or handling tokens.
///
/// Every variant is a specific reason for rejection. The distinction
/// matters: a nonce variant tells the client to retry with a fresh
/// nonce, while the others are final rejections.
///
/// # Example
///
/// ```
/// use dpop_auth::DpopError;
///
/// let err = DpopError::InvalidTyp("bearer".to_string());
/// assert_eq!(err.to_string(), "invalid typ: expected dpop+jwt, got bearer");
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DpopError {
    /// The request is missing the `DPoP` header.
    #[error("missing DPoP header")]
    MissingHeader,

    /// The `typ` JOSE header is not `dpop+jwt`.
    #[error("invalid typ: expected dpop+jwt, got {0}")]
    InvalidTyp(String),

    /// The `alg` header is not an allowed asymmetric algorithm.
    #[error("symmetric or unsupported algorithm: {0}")]
    InvalidAlgorithm(String),

    /// The proof signature or structure is invalid.
    #[error("proof signature or structure invalid: {0}")]
    InvalidSignature(String),

    /// The `htm` claim does not match the request method.
    #[error("htm mismatch: expected {expected}, got {got}")]
    HtmMismatch {
        /// The expected HTTP method from the request.
        expected: String,
        /// The actual HTTP method found in the DPoP proof token.
        got: String,
    },

    /// The `htu` claim does not match the request URI.
    #[error("htu mismatch or invalid URI")]
    HtuMismatch,

    /// The `jti` claim was already seen (replay attack).
    #[error("jti replay detected")]
    JtiReplay,

    /// The proof is outside the accepted time window (`iat`).
    #[error("proof expired (iat out of window)")]
    Expired,

    /// A nonce is required on the token endpoint (RFC 9449 section 8).
    #[error("nonce required on token endpoint")]
    TokenNonceRequired(String),

    /// A nonce is required on a protected resource (RFC 9449 section 9).
    #[error("nonce required on protected resource")]
    ResourceNonceRequired(String),

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_typ_display() {
        let err = DpopError::InvalidTyp("bearer".into());
        assert_eq!(
            err.to_string(),
            "invalid typ: expected dpop+jwt, got bearer"
        )
    }

    #[test]
    fn htm_mismatch_display() {
        let err = DpopError::HtmMismatch {
            expected: "POST".into(),
            got: "GET".into(),
        };
        assert_eq!(err.to_string(), "htm mismatch: expected POST, got GET");
    }

    #[test]
    fn nonce_variants_carry_nonce() {
        let nonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v".to_string();

        match DpopError::TokenNonceRequired(nonce.clone()) {
            DpopError::TokenNonceRequired(n) => assert_eq!(n, nonce),
            _ => panic!("expected TokenNonceRequired"),
        }

        match DpopError::ResourceNonceRequired(nonce.clone()) {
            DpopError::ResourceNonceRequired(n) => assert_eq!(n, nonce),
            _ => panic!("expected ResourceNonceRequired"),
        }
    }
}
