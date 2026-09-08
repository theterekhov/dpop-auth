# dpop-auth

[![Crates.io](https://img.shields.io/crates/v/dpop-auth.svg)](https://crates.io/crates/dpop-auth)
[![Docs.rs](https://docs.rs/dpop-auth/badge.svg)](https://docs.rs/dpop-auth)
[![License](https://img.shields.io/crates/l/dpop-auth.svg)](https://choosealicense.com/licenses/mit/)

DPoP (RFC 9449) library for Axum.

[Русская версия](README.ru.md)

`dpop-auth` provides sender-constrained access tokens, opaque refresh tokens with rotation (RFC 9700), and a PostgreSQL storage layer with Row-Level Security (RLS) tenant isolation.

## Features

- DPoP proof validation: `typ`, `alg`, `jwk`, `htm`, `htu`, `iat`, `ath`, with replay protection via `jti` caching.
- Refresh token rotation with configurable grace period and automatic family revocation on reuse.
- Stateless resource servers: access tokens are signed with ES256 and bound to the client's public key (`cnf.jkt`).
- PostgreSQL store (feature `postgres`): `UUIDv7` primary keys, RLS tenant isolation via `SET LOCAL`, login-attempt throttling.
- Transactional email outbox with `FOR UPDATE SKIP LOCKED`.
- Optional TOTP two-factor authentication (feature `totp`).

## Cargo Features

The library is completely modular. All features are opt-in (default is just the DPoP core):
- `postgres` — provides `AuthService`, storage layer, migrations, and tenant isolation.
- `totp` — two-factor authentication (TOTP) and single-use recovery codes.
- `email` — transactional outbox worker for email dispatching.
- `cookie` — helpers for delivering refresh tokens via `HttpOnly` cookies.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
dpop-auth = { version = "0.1.0", features = ["postgres"] }
```

Axum middleware example:

```rust
use axum::{Router, routing::get};
use dpop_auth::{DpopConfig, DpopState, DpopLayer, TokenSigner};

#[tokio::main]
async fn main() {
    let config = DpopConfig::builder()
        .public_url("https://api.example.com")
        .signer(TokenSigner::symmetric(b"your-32-byte-long-secret-key-here").unwrap())
        .build()
        .unwrap();

    let state = DpopState::new(config);

    let app = Router::new()
        .route("/protected", get(|| async { "Access Granted" }))
        .layer(DpopLayer::new(state.clone()))
        .with_state(state);

    // axum::serve(app, "0.0.0.0:3000").await.unwrap();
}
```

## Examples

Check out the `examples/` directory for full working demos:
- `examples/server` — a complete Axum server with database integration, CORS, and authentication.
- `examples/web` — a WebAssembly (WASM) Leptos client demonstrating in-browser DPoP proof generation using the WebCrypto API and IndexedDB key persistence.

## Deployment notes

The library stores only SHA-256 hashes of refresh tokens. The grace period of RFC 9700 is kept in an in-memory `moka` cache, so in a multi-node setup (for example Kubernetes) enable IP Hash / sticky sessions on the load balancer. If a retry hits another instance, reuse detection will revoke the whole token family.

The `/login` path is throttled via `dpop_login_attempts`, but `/register` is intentionally not rate-limited by the library, so protect it at the infrastructure level (for example with Nginx or Cloudflare).

## License

MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
