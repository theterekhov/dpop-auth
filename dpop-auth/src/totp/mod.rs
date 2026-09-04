//! TOTP (RFC 6238) helpers and recovery codes (feature `totp`).

use totp_rs::{Algorithm, Builder, Secret, Totp};

use crate::{DpopError, crypto::hash_token};

/// Number of digits in generated TOTP verification codes.
const TOTP_DIGITS: u8 = 6;

/// Allowable time drift in steps (1 step backwards and 1 step forwards).
const TOTP_SKEW: u16 = 1;

/// Time step duration in seconds (RFC 6238 default).
const TOTP_STEP: u64 = 30;

/// Output of a newly initialized TOTP enrollment flow.
#[derive(Debug, Clone)]
pub struct TotpSetup {
    /// The unpadded Base32-encoded shared secret for manual client entry.
    pub secret_base32: String,
    /// The complete `otpauth://totp/...` URI formatted for QR code generation.
    pub otpauth_url: String,
}

/// Construct an internal [`Totp`] validator instance from Base32-encoded secret.
///
/// Parameters `account_name` and `issuer`  are metadata used exclusively when
/// constructing the `otpauth://` URI and do not alter the calculated
/// code values.
///
/// # Errors
///
/// Returns [`DpopError::Internal`] if `secret_base32` cannot be decoded
/// as valid Base32 or if configuring the TOTP validator fails.
fn build_totp(
    secret_base32: &str,
    issuer: Option<&str>,
    account_name: Option<&str>,
) -> Result<Totp, DpopError> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|e| DpopError::Internal(format!("invalid TOTP secret: {e}")))?;

    let mut builder = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(TOTP_DIGITS)
        .with_skew(TOTP_SKEW)
        .with_step_duration(TOTP_STEP)
        .with_secret(secret)
        .with_account_name(account_name.unwrap_or(""));

    if let Some(issuer) = issuer {
        builder = builder.with_issuer(Some(issuer));
    }

    builder
        .build()
        .map_err(|e| DpopError::Internal(format!("failed to build TOTP: {e}")))
}

/// Reconstruct a [`TotpSetup`] instance from a previously stored Base32 secret.
///
/// Re-generates the configuration and URI for an existing pending
/// secret without rotating the key material.
///
/// # Errors
///
/// Returns [`DpopError::Internal`] if `secret_base32` is malformed
/// or URI generation fails.
pub(crate) fn setup_from_secret(
    secret_base32: &str,
    issuer: &str,
    account_name: &str,
) -> Result<TotpSetup, DpopError> {
    let totp = build_totp(secret_base32, Some(issuer), Some(account_name))?;

    let otpauth_url = totp
        .to_url()
        .map_err(|e| DpopError::Internal(format!("failed to build otpauth URL: {e}")))?;

    Ok(TotpSetup {
        secret_base32: totp.secret().to_base32(),
        otpauth_url,
    })
}

/// Generate a fresh 160-bit random TOTP setup for a user.
///
/// Generates a cryptographically secure 160-bit shared secret as recommended
/// by RFC 4226 section 4, returning both the Base32 representation and the
/// registration URL.
///
/// # Errors
///
/// Returns [`DpopError::Internal`] if the internal validator or `otpauth://` URI
/// construction fails.
pub fn generate_setup(issuer: &str, account_name: &str) -> Result<TotpSetup, DpopError> {
    let secret = Secret::generate();
    setup_from_secret(&secret.to_base32(), issuer, account_name)
}

/// Verify a single TOTP verification code against an existing Base32 secret.
///
/// Compares the provided code against the valid window using the current system
/// timestamp and configured clock skew (30 seconds).
///
/// # Security Note
///
/// Callers must enforce replay protection (RFC 6238 section 5.2) to prevent
/// multiple uses of the same code within its acceptance window.
#[must_use]
pub fn verify_code(secret_base32: &str, code: &str) -> bool {
    match build_totp(secret_base32, None, None) {
        Ok(totp) => totp.check_current(code.trim()).is_some(),
        Err(_) => false,
    }
}

/// Generate a single cryptographically secure recovery code
/// (80 bits of entropy).
///
/// Returns a 23-character string separated into four hyphenated 5-character
/// hexadecimal blocks: `XXXXX-XXXXX-XXXXX-XXXXX`.
///
/// # Errors
///
/// Returns [`DpopError::Internal`] if the operating system entropy source fails.
pub fn generate_recovery_code() -> Result<String, DpopError> {
    let mut bytes = [0_u8; 10];
    getrandom::fill(&mut bytes).map_err(|e| DpopError::Internal(e.to_string()))?;

    let hex = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}",
        &hex[0..5],
        &hex[5..10],
        &hex[11..15],
        &hex[16..20]
    ))
}

/// Generate a batch of distinct recovery codes using a single
/// operating system entropy call.
///
/// Reads `count * 10` contiguous random bytes in one system
/// invocation to reduce context-switch overhead when provisioning
/// a complete recovery code set.
///
/// # Errors
///
/// Returns [`DpopError::Internal`] in the operating system entropy source fails.
pub fn generate_recovery_codes(count: usize) -> Result<Vec<String>, DpopError> {
    let mut bytes = vec![0_u8; count * 10];
    getrandom::fill(&mut bytes).map_err(|e| DpopError::Internal(e.to_string()))?;

    Ok(bytes
        .as_chunks::<10>()
        .0
        .iter()
        .map(|chunk| {
            let hex = hex::encode(chunk);

            format!(
                "{}-{}-{}-{}",
                &hex[0..5],
                &hex[5..10],
                &hex[10..15],
                &hex[15..20]
            )
        })
        .collect())
}

/// Compute a normalized cryptographic hash of a recovery code
/// for database storage.
///
/// Normalizes the code (stripping leading/trailing whitespace and lowercasing)
/// before computing its SHA-256 digest to ensure entry formatting does not
/// prevent valid matching.
#[must_use]
pub fn hash_recovery_code(code: &str) -> String {
    hash_token(code.trim().to_lowercase().as_bytes())
}

/// Inspect whether a raw input string matches the recovery code format.
///
/// Returns `true` if the input composed of exactly 23 characters matching
/// four hyphen-separated groups of five hexadecimal ASCII characters
/// (`XXXXX-XXXXX-XXXXX-XXXXX`). Used to route login requests between TOTP codes
/// and recovery codes.
#[must_use]
pub fn is_recovery_code(code: &str) -> bool {
    let code = code.trim();
    if code.len() != 23 {
        return false;
    }

    let mut groups = code.split('-');
    groups.clone().count() == 4
        && groups.all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_hexdigit()))
}
