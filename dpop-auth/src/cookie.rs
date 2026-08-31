//! Refresh-token cookie helpers (feature `cookie`).

use axum_extra::extract::cookie::{Cookie, SameSite as CookieSameSite};
use time::Duration as TimeDuration;

use crate::config::{CookieConfig, SameSite};

/// Build a `Set-Cookie` header value carrying the refresh token.
///
/// Applies the attributes from `CookieConfig` (`__Host-` prefix, `Secure`,
/// `HttpOnly`, `SameSite`, `Max-Age`).
pub fn refresh_token_cookie(config: &CookieConfig, value: &str) -> String {
    let mut cookie = Cookie::new(config.name.clone(), value.to_string());

    cookie.set_path(config.path.clone());
    cookie.set_secure(config.secure);
    cookie.set_http_only(config.http_only);
    cookie.set_same_site(match config.same_site {
        SameSite::Strict => CookieSameSite::Strict,
        SameSite::Lax => CookieSameSite::Lax,
        SameSite::None => CookieSameSite::None,
    });

    let max_age_secs = i64::try_from(config.max_age.as_secs()).unwrap_or(i64::MAX);
    cookie.set_max_age(TimeDuration::seconds(max_age_secs));

    cookie.encoded().to_string()
}

/// Read a cookie value from a `Cookie` header, if present.
pub fn read_cookie(cookie_header: &str, name: &str) -> Option<String> {
    Cookie::split_parse(cookie_header)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_string())
}
