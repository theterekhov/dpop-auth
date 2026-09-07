use std::net::SocketAddr;

use dpop_auth::{
    DpopConfig,
    store::{create_pool, run_migrations},
};
use server::create_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if dotenvy::dotenv().is_err() {
        let _ = dotenvy::from_filename("examples/server/.env");
    }
    tracing_subscriber::fmt::init();

    let config = DpopConfig::from_env()?;
    let pool = create_pool(&std::env::var("DATABASE_URL")?).await?;
    run_migrations(&pool).await?;

    let app = create_app(config, pool).await;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
