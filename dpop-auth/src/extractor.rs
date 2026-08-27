//! The `DpopSession` extractor.

use axum::extract::FromRequestParts;
use serde::de::DeserializeOwned;

use crate::DpopError;

/// The authenticated session, extracted by handlers.
#[derive(Debug, Clone)]
pub struct DpopSession<T = ()> {
    /// Subject identifier (the authenticated user).
    pub sub: String,
    /// The access token's `jti`.
    pub jti: String,
    /// The `cnf.jkt` thumbprint the token is bound to.
    pub jkt: String,
    /// Application-specific claims.
    pub claims: T,
}

/// Internal session data injected by the middleware.
#[derive(Debug, Clone)]
pub(crate) struct ValidatedSession {
    pub sub: String,
    pub jti: String,
    pub jkt: String,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Decode the extra claims of an access token into a concrete type.
pub trait FromExtra: Sized + Send + Sync + 'static {
    /// Build the claims from the token's extra JSON subject.
    fn from_extra(extra: serde_json::Map<String, serde_json::Value>) -> Result<Self, DpopError>;
}

impl FromExtra for () {
    fn from_extra(_extra: serde_json::Map<String, serde_json::Value>) -> Result<Self, DpopError> {
        Ok(())
    }
}

/// Deserialize the extra claims into `DeserializeOwned` type.
pub fn deserialize_extra<T: DeserializeOwned + Send + Sync + 'static>(
    extra: serde_json::Map<String, serde_json::Value>,
) -> Result<T, DpopError> {
    serde_json::from_value(serde_json::Value::Object(extra))
        .map_err(|e| DpopError::Internal(e.to_string()))
}

/// Implement [`FromExtra`] for a type that derives `Deserialize`.
#[macro_export]
macro_rules! impl_from_extra {
    ($t:ty) => {
        impl $crate::extractor::FromExtra for $t {
            fn from_extra(
                extra: serde_json::Map<String, serde_json::Value>,
            ) -> Result<Self, $crate::DpopError> {
                $crate::extractor::deserialize_extra(extra)
            }
        }
    };
}

impl<S, T> FromRequestParts<S> for DpopSession<T>
where
    S: Send + Sync,
    T: FromExtra,
{
    type Rejection = DpopError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<ValidatedSession>()
            .cloned()
            .ok_or(DpopError::MissingHeader)?;

        let claims = T::from_extra(session.extra)?;

        Ok(DpopSession {
            sub: session.sub,
            jti: session.jti,
            jkt: session.jkt,
            claims,
        })
    }
}
