//! Persist the non-extractable key pair in IndexedDB via Structured Clone.
//!
//! # Architecture & Security Disclaimer
//!
//! 1. Platform Limitations (Mozilla Firefox - Bugzilla #1348279):
//!    Firefox's Gecko engine (backed by NSS) fails to serialize `CryptoKey`
//!    descriptors into IndexedDB via structured cloning, throwing a `DomException`.
//!    This implementation strictly relies on W3C Structured Clone semantics supported
//!    by Chromium (Blink) and WebKit (Safari).
//!
//! 2. Security Trade-offs (RFC 9449 & Browser Thread Model):
//!    - Storing `CryptoKeyPair` with `extractable = false` protests against direct key
//!      theft via JavaScript memory dumping, but remains vulnerable to In-Session Oracle
//!      Attacks if an attacker achieves XSS execution on the origin.
//!    - A production-grade deployment adhering to IETF Oauth 2.0 Best Current Practices
//!      for Browser-Based Apps should eliminate client-side key storage entirely using
//!      a Backend-for-Frontend (BFF) proxy with `HttpOnly` cookies, or leverage in-memory
//!      lazy re-binding (`draft-rosomakho-oauth-dpop-rt`) / WebAuth PRF key derivation.
//!
//! 3. Wasm Resource Management:
//!    `Closure::once` event listeners are used for lightweight demonstration.
//!    For high-throughput production workloads, an abstraction crate (such as `idb` or
//!    `indexed_db_futures`) should be adopted to guarantee deterministic RAII
//!    cleanup across edge-case transaction aborts.

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt, prelude::Closure};
use web_sys::{CryptoKeyPair, IdbDatabase, IdbOpenDbRequest, IdbTransactionMode};

const DB_NAME: &str = "dpop-keys";
const STORE: &str = "keys";

pub async fn open() -> Result<IdbDatabase, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let idb = window
        .indexed_db()?
        .ok_or_else(|| JsValue::from_str("indexed_db_unavailable"))?;

    let request = idb.open_with_u32(DB_NAME, 1)?;

    let on_upgrade = Closure::once(move |e: web_sys::Event| {
        let event: web_sys::IdbVersionChangeEvent = e.dyn_into().unwrap_throw();
        let target: IdbOpenDbRequest = event.target().unwrap_throw().dyn_into().unwrap_throw();
        let db: IdbDatabase = target.result().unwrap_throw().dyn_into().unwrap_throw();

        if !db.object_store_names().contains(STORE) {
            db.create_object_store(STORE).unwrap_throw();
        }
    });

    let upgrade_fn: js_sys::Function = on_upgrade.into_js_value().unchecked_into();
    request.set_onupgradeneeded(Some(&upgrade_fn));

    let (tx, rx) = futures_channel::oneshot::channel();
    let req_clone = request.clone();
    let on_success = Closure::once(move |_e: web_sys::Event| {
        let db: IdbDatabase = req_clone.result().unwrap_throw().dyn_into().unwrap_throw();
        let _ = tx.send(Ok(db));
    });
    let success_fn: js_sys::Function = on_success.into_js_value().unchecked_into();
    request.set_onsuccess(Some(&success_fn));

    rx.await.map_err(|_| JsValue::from_str("open cancelled"))?
}

pub async fn save_key_pair(db: &IdbDatabase, key_pair: &CryptoKeyPair) -> Result<(), JsValue> {
    let tx = db.transaction_with_str_and_mode(STORE, IdbTransactionMode::Readwrite)?;
    let store = tx.object_store(STORE)?;
    store.put_with_key(key_pair.as_ref(), &"keypair".into())?;

    Ok(())
}

pub async fn load_key_pair(db: &IdbDatabase) -> Result<Option<CryptoKeyPair>, JsValue> {
    let tx = db.transaction_with_str_and_mode(STORE, IdbTransactionMode::Readonly)?;
    let store = tx.object_store(STORE)?;
    let requests = store.get(&"keypair".into())?;

    let (tx, rx) = futures_channel::oneshot::channel();
    let req_clone = requests.clone();
    let on_success = Closure::once(move |_e: web_sys::Event| {
        let res = req_clone.result().ok();
        let _ = tx.send(res);
    });
    let success_fn: js_sys::Function = on_success.into_js_value().unchecked_into();
    requests.set_onsuccess(Some(&success_fn));

    let value = rx.await.map_err(|_| JsValue::from_str("get cancelled"))?;
    Ok(value
        .filter(|v| !v.is_null() && !v.is_undefined())
        .map(|v| v.unchecked_into::<CryptoKeyPair>()))
}
