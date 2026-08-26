//! Runtime configuration for the DPoP authentication library.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

use crate::DpopError;

/// Signing strategy for access tokens.
///
/// - `Symmetric` signs and verifies with one shared secret (HS256).
///   Simple for a monolithic development.
/// - `Asymmetric` signs with a private key and verifies with the public key (ES256).
///   Resource servers then only need the public key, which enables
///   decentralized deployments.
#[derive(Debug, Clone)]
pub enum TokenSigner {
    /// HMAC-SHA256 with a shared secret.
    Symmetric(Arc<EncodingKey>, Arc<DecodingKey>),
    /// ECDSA P-256 with a private/public key pair.
    Asymmetric(Arc<EncodingKey>, Arc<DecodingKey>),
}

impl TokenSigner {
    /// Crate a symmetric (HS256) signer from a shared secret.
    pub fn symmetric(secret: &[u8]) -> Self {
        Self::Symmetric(
            Arc::new(EncodingKey::from_secret(secret)),
            Arc::new(DecodingKey::from_secret(secret)),
        )
    }

    /// Create an asymmetric (ES256) signer from an EC key pair.
    pub fn asymmetric(encoding_key: EncodingKey, decoding_key: DecodingKey) -> Self {
        Self::Asymmetric(Arc::new(encoding_key), Arc::new(decoding_key))
    }

    /// The JWS algorithm used by this signer.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Symmetric(..) => Algorithm::HS256,
            Self::Asymmetric(..) => Algorithm::ES256,
        }
    }

    /// The key used to sign tokens (issuer side).
    pub fn encoding_key(&self) -> &EncodingKey {
        match self {
            Self::Symmetric(key, _) | Self::Asymmetric(key, _) => key,
        }
    }

    /// The key used to verify tokens (resource server side).
    pub fn decoding_key(&self) -> &DecodingKey {
        match self {
            Self::Symmetric(_, key) | Self::Asymmetric(_, key) => key,
        }
    }
}

/// The `SameSite` cookie attribute.
#[cfg(feature = "cookie")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SameSite {
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=Lax`.
    Lax,
    /// No `SameSite` attribute.
    None,
}

/// How the refresh token is delivered
/// (only with the `cookie` feature).
#[cfg(feature = "cookie")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CookieConfig {
    /// Cookie name, using the `__Host-` prefix
    /// for maximum isolation.
    pub name: String,
    /// Cookie path.
    pub path: String,
    /// `Secure` attribute.
    pub secure: bool,
    /// `HttpOnly` attribute.
    pub http_only: bool,
    /// `SameSite` attribute.
    pub same_site: SameSite,
    /// Cookie lifetime.
    pub max_age: Duration,
}

#[cfg(feature = "cookie")]
impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "__Host-dpop_refresh".to_string(),
            path: "/api/auth".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Strict,
            max_age: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

/// Library-wide configuration.
///
/// Not constructed with a literal;
/// use [`DpopConfig::builder`] or [`DpopConfig::from_env`].
/// New fields can be added in mirror releases.
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// Public base URL, used to build and check `htu` values.
    pub public_url: String,
    /// The `iss` claim of issued access tokens.
    pub issuer: String,
    /// The `aud` claim of issued access tokens.
    pub audience: String,
    /// Allowed clock drift when checking `iat` and `exp`.
    pub clock_skew: Duration,
    /// Whether a server-issued nonce is required in every proof.
    pub nonce_required: bool,
    /// JWS algorithms accepted for DPoP proofs.
    pub allowed_algs: Vec<Algorithm>,
    /// Signer used to issue and verify access tokens.
    pub signer: TokenSigner,
    /// Lifetime of access tokens.
    pub access_token_ttl: Duration,
    /// Lifetime of refresh tokens.
    pub refresh_token_ttl: Duration,
    /// Reuse-detection grace window for refresh token rotation.
    pub grace_period: Duration,
    /// Whether new users can register themselves.
    pub allow_registration: bool,
    /// Refresh-token cookie settings
    /// (only with the `cookie` feature).
    #[cfg(feature = "cookie")]
    pub cookie: CookieConfig,
}

impl DpopConfig {
    /// Start building a configuration.
    pub fn builder() -> DpopConfigBuilder {
        DpopConfigBuilder::default()
    }

    /// Build a symmetric configuration from environment variables.
    ///
    /// Reads `DPOP_PUBLIC_URL` and `JWT_SECRET`. Everything else uses
    /// builder defaults.
    pub fn from_env() -> Result<Self, DpopError> {
        let public_url = std::env::var("DPOP_PUBLIC_URL")
            .map_err(|_| DpopError::Internal("DPOP_PUBLIC_URL is not set".into()))?;
        let secret = std::env::var("JWT_SECRET")
            .map_err(|_| DpopError::Internal("JWT_SECRET is not set".into()))?;

        let signer = TokenSigner::symmetric(secret.as_bytes());

        Self::builder()
            .public_url(public_url)
            .signer(signer)
            .build()
    }
}

/// Builder for [`DpopConfig`]
pub struct DpopConfigBuilder {
    public_url: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    clock_skew: Duration,
    nonce_required: bool,
    allowed_algs: Vec<Algorithm>,
    signer: Option<TokenSigner>,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    grace_period: Duration,
    allow_registration: bool,
    #[cfg(feature = "cookie")]
    cookie: CookieConfig,
}

impl Default for DpopConfigBuilder {
    fn default() -> Self {
        Self {
            public_url: None,
            issuer: None,
            audience: None,
            clock_skew: Duration::from_secs(60),
            nonce_required: false,
            allowed_algs: vec![Algorithm::ES256, Algorithm::PS256],
            signer: None,
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            grace_period: Duration::from_secs(5),
            allow_registration: true,
            #[cfg(feature = "cookie")]
            cookie: CookieConfig::default(),
        }
    }
}

impl DpopConfigBuilder {
    /// Set the public base URL (required).
    pub fn public_url(mut self, value: impl Into<String>) -> Self {
        self.public_url = Some(value.into());
        self
    }

    /// Set the issuer; defaults to the public URL.
    pub fn issuer(mut self, value: impl Into<String>) -> Self {
        self.issuer = Some(value.into());
        self
    }

    /// Set the audience; defaults to the public URL.
    pub fn audience(mut self, value: impl Into<String>) -> Self {
        self.audience = Some(value.into());
        self
    }

    /// Set the allowed clock skew.
    pub fn clock_skew(mut self, value: Duration) -> Self {
        self.clock_skew = value;
        self
    }

    /// Set whether proofs must carry a nonce.
    pub fn nonce_required(mut self, value: bool) -> Self {
        self.nonce_required = value;
        self
    }

    /// Set the accepted proof algorithms.
    pub fn allowed_algs(mut self, value: Vec<Algorithm>) -> Self {
        self.allowed_algs = value;
        self
    }

    /// Set the access-token signer (required).
    pub fn signer(mut self, value: TokenSigner) -> Self {
        self.signer = Some(value);
        self
    }

    /// Set the access-token lifetime.
    pub fn access_token_ttl(mut self, value: Duration) -> Self {
        self.access_token_ttl = value;
        self
    }

    /// Set the refresh-token lifetime.
    pub fn refresh_token_ttl(mut self, value: Duration) -> Self {
        self.refresh_token_ttl = value;
        self
    }

    /// Set the refresh-token rotation grace period.
    pub fn grace_period(mut self, value: Duration) -> Self {
        self.grace_period = value;
        self
    }

    /// Set whether self-registration is allowed.
    pub fn allow_registration(mut self, value: bool) -> Self {
        self.allow_registration = value;
        self
    }

    /// Set the refresh-token cookie settings.
    #[cfg(feature = "cookie")]
    pub fn cookie(mut self, value: CookieConfig) -> Self {
        self.cookie = value;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<DpopConfig, DpopError> {
        let public_url = self
            .public_url
            .ok_or_else(|| DpopError::Internal("public_url is required".into()))?;
        let signer = self
            .signer
            .ok_or_else(|| DpopError::Internal("signer is required".into()))?;

        let issuer = self.issuer.unwrap_or_else(|| public_url.clone());
        let audience = self.audience.unwrap_or_else(|| public_url.clone());

        Ok(DpopConfig {
            public_url,
            issuer,
            audience,
            clock_skew: self.clock_skew,
            nonce_required: self.nonce_required,
            allowed_algs: self.allowed_algs,
            signer,
            access_token_ttl: self.access_token_ttl,
            refresh_token_ttl: self.refresh_token_ttl,
            grace_period: self.grace_period,
            allow_registration: self.allow_registration,
            #[cfg(feature = "cookie")]
            cookie: self.cookie,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn base_builder() -> DpopConfigBuilder {
        DpopConfig::builder()
            .public_url("https://auth.example.com")
            .signer(TokenSigner::symmetric(b"test-secret"))
    }

    #[test]
    fn builder_applies_defaults() {
        let config = base_builder().build().unwrap();

        assert_eq!(config.public_url, "https://auth.example.com");
        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.audience, "https://auth.example.com");
        assert_eq!(config.clock_skew, Duration::from_secs(60));
        assert!(!config.nonce_required);
        assert_eq!(
            config.allowed_algs,
            vec![Algorithm::ES256, Algorithm::PS256]
        );
        assert_eq!(config.access_token_ttl, Duration::from_secs(900));
        assert_eq!(
            config.refresh_token_ttl,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert_eq!(config.grace_period, Duration::from_secs(5));
        assert!(config.allow_registration);
    }

    #[test]
    fn issuer_and_audience_override() {
        let config = base_builder()
            .issuer("https://issuer.example.com")
            .audience("my-api")
            .clock_skew(Duration::from_secs(120))
            .nonce_required(true)
            .build()
            .unwrap();

        assert_eq!(config.issuer, "https://issuer.example.com");
        assert_eq!(config.audience, "my-api");
        assert_eq!(config.clock_skew, Duration::from_secs(120));
        assert!(config.nonce_required);
    }

    #[test]
    fn build_requires_public_url() {
        let result = DpopConfig::builder()
            .signer(TokenSigner::symmetric(b"secret"))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn from_env_errors_without_vars() {
        assert!(DpopConfig::from_env().is_err());
    }

    #[test]
    fn signer_algorithm_is_correct() {
        assert_eq!(TokenSigner::symmetric(b"x").algorithm(), Algorithm::HS256);
    }

    #[cfg(feature = "cookie")]
    #[test]
    fn cookie_defaults() {
        let cookie = CookieConfig::default();

        assert_eq!(cookie.name, "__Host-dpop_refresh");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, SameSite::Strict);
    }
}
