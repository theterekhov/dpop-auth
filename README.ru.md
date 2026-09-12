# dpop-auth

[![Crates.io](https://img.shields.io/crates/v/dpop-auth.svg)](https://crates.io/crates/dpop-auth)
[![Docs.rs](https://docs.rs/dpop-auth/badge.svg)](https://docs.rs/dpop-auth)
[![License](https://img.shields.io/github/license/theterekhov/dpop-auth.svg)](LICENSE-MIT)

Библиотека DPoP (RFC 9449) для Axum.

[English](README.md)

`dpop-auth` реализует sender-constrained access токены, ротацию opaque refresh токенов (RFC 9700) и слой хранения на PostgreSQL с изоляцией тенантов через Row-Level Security (RLS).

## Возможности

- Валидация DPoP proof: `typ`, `alg`, `jwk`, `htm`, `htu`, `iat`, `ath`, защита от повторного использования через кэширование `jti`.
- Ротация refresh токенов с настраиваемым grace-периодом и автоматическим отзывом всего семейства токенов при переиспользовании.
- Stateless resource servers: access токены подписаны ES256 и привязаны к публичному ключу клиента (`cnf.jkt`).
- Хранилище PostgreSQL (фича `postgres`): первичные ключи `UUIDv7`, изоляция тенантов через RLS (`SET LOCAL`), лимит попыток входа.
- Transactional outbox для email с `FOR UPDATE SKIP LOCKED`.
- Опциональная двухфакторная аутентификация TOTP (фича `totp`).

## Feature-флаги

Библиотека спроектирована модульно. По умолчанию все фичи отключены (только ядро DPoP):
- `postgres` — реализация `AuthService`, слой хранения, миграции и изоляция тенантов.
- `totp` — логика двухфакторной аутентификации (TOTP) и одноразовые коды восстановления.
- `email` — transactional outbox воркер для отправки писем.
- `cookie` — хелперы для передачи refresh токенов через `HttpOnly` cookie.
- `derive` — процедурный макрос `#[derive(FromExtra)]` для автоматической десериализации пользовательских клеймов.

## Быстрый старт

Добавьте в `Cargo.toml`:

```toml
[dependencies]
dpop-auth = { version = "0.1.0", features = ["postgres"] }
```

Пример с middleware для Axum:

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
        .route("/protected", get(|| async { "Доступ разрешен" }))
        .layer(DpopLayer::new(state.clone()))
        .with_state(state);

    // axum::serve(app, "0.0.0.0:3000").await.unwrap();
}
```

## Примеры (Examples)

В репозитории есть готовые примеры использования:
- `examples/server` — полноценный Axum-сервер с настроенной СУБД, CORS и аутентификацией.
- `examples/web` — клиентское WebAssembly (WASM) приложение на фреймворке Leptos, генерирующее DPoP proof'ы через браузерный WebCrypto API и хранящее ключи в IndexedDB.

## Заметки по развертыванию

Библиотека хранит только SHA-256 хэши refresh токенов. Grace-период из RFC 9700 живёт в in-memory кэше `moka`, поэтому в кластере (например, Kubernetes) на балансировщике нужно включить IP Hash / sticky sessions. Если retry попадёт на другой инстанс, защита от переиспользования отзовёт всё семейство токенов.

Эндпоинт `/login` ограничивается через `dpop_login_attempts`, но `/register` библиотека намеренно не лимитирует — защитите его на уровне инфраструктуры (например, Nginx или Cloudflare).

## Лицензия

MIT или Apache-2.0 на ваш выбор. См. [LICENSE-MIT](LICENSE-MIT) и [LICENSE-APACHE](LICENSE-APACHE).
