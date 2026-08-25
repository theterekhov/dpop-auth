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
/// (RFC 9449 sectrion 6.1).
///
/// # Example
///
/// ```
/// use dpop_auth::{crypto::compute_jwk_thumbprint, Jwk};
///
/// let jwk: Jwk = serde_json::from_str(
/// 	r#"{"kty":"EC","crv":"P-256","x":"...","y":"..."}"#
/// ).unwrap();
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
/// cannot be replayed with a different token (RFC 9449 sectrion 4.2).
///
/// # Example
///
/// ```
/// use dpop_auth::crypto::compute_ath;
///
/// let ath = compute_ath("access-token-value");
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
/// assert_eq!(hash.len(), 64);
/// ```
pub fn hash_token(secret: &[u8]) -> String {
    hex::encode(Sha256::digest(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic() {
        let secret = [0x42_u8; 32];
        assert_eq!(hash_token(&secret), hash_token(&secret));
    }

    #[test]
    fn hash_token_is_64_chars_hex() {
        let secret = [0x42_u8; 32];
        let hash = hash_token(&secret);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_differs_for_different_secrets() {
        let a = [0x42_u8; 32];
        let b = [0x43_u8; 32];
        assert_ne!(hash_token(&a), hash_token(&b));
    }

    #[test]
    fn hash_token_does_not_leak_secret() {
        let secret = b"super-secret-refresh-token-value";
        assert!(!hash_token(secret).contains("secret"));
    }

    #[test]
    fn ath_is_base64url_sha256() {
        let ath = compute_ath("abc");
        assert!(!ath.contains('+') && !ath.contains('/') && !ath.contains('='));
        assert_eq!(ath, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    }

    #[test]
    fn ath_differs_for_different_tokens() {
        assert_ne!(compute_ath("token-a"), compute_ath("token-b"));
    }

    #[test]
    fn thumbprint_matches_ec_vector() {
        let jwk: Jwk = serde_json::from_str(
           r#"{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}"#,
       )
       .unwrap();

        assert_eq!(
            compute_jwk_thumbprint(&jwk).unwrap(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn thumbprint_matches_rsa_vector() {
        let jwk: Jwk = serde_json::from_str(
            r#"{
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "kid": "2011-04-29"
            }"#,
        )
        .unwrap();

        assert_eq!(
            compute_jwk_thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn thumbprint_ignores_extra_members() {
        let a: Jwk = serde_json::from_str(
            r#"{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}"#,
        )
        .unwrap();
        let b: Jwk = serde_json::from_str(
            r#"{"kid":"my-key","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","crv":"P-256","kty":"EC","alg":"ES256"}"#,
        )
        .unwrap();

        assert_eq!(
            compute_jwk_thumbprint(&a).unwrap(),
            compute_jwk_thumbprint(&b).unwrap()
        );
    }
}
