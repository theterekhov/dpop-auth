//! Cryptographic primitives for DPoP: JWK thumbprint (RFC 7638), the `ath`
//! claim (base64url SHA-256 of the access token), and opaque token hashing.

use base64ct::{Base64UrlUnpadded, Encoding};
use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use sha2::{Digest, Sha256};

use crate::DpopError;

/// Compute the JWK SHA-256 thumbprint (RFC 7638).
///
/// The thumbprint is a canonical hash of the public key: only the
/// required JWK members are serialized in a canonical order and hashed
/// with SHA-256. It is used as the `cnf.jkt` value in access tokens
/// (RFC 9449 p.6.1).
///
/// # Example
///
/// ```
/// use dpop_auth::{crypto::compute_jwk_thumbprint, Jwk};
///
/// let jwk: Jwk = serde_json::from_str(
/// 	r#"{"kty":"EC","crv":"P-256","x":"...","y":"..."}"#
/// ).unwrap();
///
/// assert_eq!(
/// 	compute_jwk_thumbprint(&jwk).unwrap(),
/// 	"2oU-IXkxSYGwbjojye-Eb9i6KU7rtzeU_Eh-01YE_44"
/// );
/// ```
pub fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    jwk.thumbprint(ThumbprintHash::SHA256)
        .map_err(|_| DpopError::InvalidSignature("failed to compute JWK thumbprint".into()))
}

/// Compute the `ath` claim: base64url(SHA-256(access_token)).
///
/// Binds a DPoP proof to a specific access token value, so a proof
/// cannot be replayed with a different token (RFC 9449 p.4.2).
///
/// # Example
///
/// ```
/// use dpop_auth::crypto::compute_ath;
///
/// let ath = compute_ath("access-token-value");
///
/// assert!(!ath.is_empty());
/// ```
pub fn compute_ath(access_token: &str) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(access_token.as_bytes()))
}

/// Hash an opaque token secret with SHA-256, hex-encoded.
///
/// Only the hash is stored in the database: a database leak must not
/// reveal usable refresh tokens. The secret has 256 bits of entropy,
/// so SHA-256 is enough (Argon2 is not needed).
///
/// # Example
///
/// ```
/// use dpop_auth::crypto::hash_token;
///
/// let hash = hash_token(b"my-refresh-token-secret");
///
/// assert_eq!(hash.len(), 64);
/// ```
pub fn hash_token(secret: &[u8]) -> String {
    hex::encode(Sha256::digest(secret))
}
