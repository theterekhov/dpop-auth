//! WebCrypto key generation, signing, and DPoP proof assembly.

use base64ct::{Base64UrlUnpadded, Encoding};
use js_sys::Uint8Array;
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, CryptoKeyPair, EcKeyGenParams, EcdsaParams, SubtleCrypto};

/// Access the browser's `SubtleCrypto`.
pub fn subtle() -> Result<SubtleCrypto, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("not window"))?;

    Ok(window.crypto()?.subtle())
}

pub async fn generate_key_pair() -> Result<CryptoKeyPair, JsValue> {
    let params = EcKeyGenParams::new("ECDSA", "P-256");

    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("sign"));

    let subtle = subtle()?;
    let promise = subtle.generate_key_with_object(params.unchecked_ref(), false, &usages)?;

    let pair = JsFuture::from(promise).await?;

    Ok(pair.unchecked_into::<CryptoKeyPair>())
}

pub async fn export_public_jwk(public: &CryptoKey) -> Result<String, JsValue> {
    let promise = subtle()?.export_key("jwk", public)?;
    let jwk = JsFuture::from(promise).await?;

    Ok(String::from(js_sys::JSON::stringify(&jwk)?))
}

pub async fn sign(private: &CryptoKey, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let params = EcdsaParams::new_with_str("ECDSA", "SHA-256");
    let promise = subtle()?.sign_with_object_and_u8_array(params.unchecked_ref(), private, data)?;
    let signature = JsFuture::from(promise).await?;

    Ok(Uint8Array::new(&signature).to_vec())
}

pub fn compute_ath(access_token: &str) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(access_token.as_bytes()))
}

pub fn build_proof_signing_input(
    jwk: &serde_json::Value,
    htm: &str,
    htu: &str,
    now: u64,
    jti: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });

    let mut claims = serde_json::json!({
        "htm": htm,
         "htu": htu,
          "iat": now,
           "jti": jti
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    if let Some(t) = access_token {
        claims["ath"] = serde_json::json!(compute_ath(t));
    }

    let header_b64 = Base64UrlUnpadded::encode_string(header.to_string().as_bytes());
    let claims_b64 = Base64UrlUnpadded::encode_string(claims.to_string().as_bytes());

    format!("{header_b64}.{claims_b64}")
}

pub async fn generate_proof(
    key_pair: &CryptoKeyPair,
    jwk: &serde_json::Value,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
) -> Result<String, JsValue> {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let jti = uuid::Uuid::new_v4().to_string();

    let signing_input = build_proof_signing_input(jwk, htm, htu, now, &jti, access_token, nonce);
    let signature = sign(&key_pair.get_private_key(), signing_input.as_bytes()).await?;
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}
