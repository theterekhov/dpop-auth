//! Manual DPoP HTTP client with nonce retry.

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKeyPair, Headers, Request, RequestInit, Response};

use crate::crypto::generate_proof;

/// A request result carrying the DPoP-Nonce challenge, if any.
pub struct DpopResponse {
    pub status: u16,
    pub headers: Headers,
    pub text: String,
}

pub async fn dpop_requests(
    key_pair: &CryptoKeyPair,
    jwk: &serde_json::Value,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    body: Option<&str>,
) -> Result<DpopResponse, JsValue> {
    let mut nonce: Option<String> = None;

    for _ in 0..2 {
        let proof =
            generate_proof(key_pair, jwk, method, url, access_token, nonce.as_deref()).await?;

        let headers = Headers::new()?;
        headers.set("DPoP", &proof)?;
        if let Some(token) = access_token {
            headers.set("Authorization", &format!("DPoP {token}"))?;
        }

        if body.is_some() {
            headers.set("Content-Type", "application/json")?;
        }

        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_headers(&headers);
        if let Some(b) = body {
            opts.set_body(&b.into());
        }

        let request = Request::new_with_str_and_init(url, &opts)?;
        let response: Response =
            JsFuture::from(web_sys::window().unwrap().fetch_with_request(&request))
                .await?
                .dyn_into()?;

        // Nonce challenge -> re-sign with the nonce and retry.
        if (response.status() == 401 || response.status() == 400)
            && let Some(n) = response.headers().get("DPoP-Nonce")?
        {
            nonce = Some(n);
            continue;
        }

        let status = response.status();
        let text = JsFuture::from(response.text()?)
            .await?
            .as_string()
            .unwrap_or_default();
        let headers = response.headers();

        return Ok(DpopResponse {
            status,
            headers,
            text,
        });
    }

    Err(JsValue::from_str("nonce retry limit reached"))
}
