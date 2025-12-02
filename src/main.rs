use crate::{
    config::CONFIG,
    database::{ConnectorRefreshToken, Database},
    oidc::{retrieve_access_and_refresh_token, retrieve_jwks},
};
use anyhow::{Context, Result};
use clap::Parser;
use oauth2::{RefreshToken, reqwest};
use openidconnect::{JsonWebKeySet, core::CoreJsonWebKey};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, error, info, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod database;
mod oidc;
mod util;

/// Refresher tool for OpenId Connect refresh tokens from the WildLIVE portal inside a Geo Engine instance.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Refresh all tokens regardless whether they are going to expire
    #[arg(short, long)]
    force: bool,

    // Run refresher every `refresh_interval` seconds
    #[arg(short, long)]
    scheduled: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let args = Args::parse();

    let comparison_duration =
        (!args.force).then(|| CONFIG.refresh_buffer_pct * CONFIG.refresh_interval);

    let mut scheduler = JobScheduler::new().await?;
    let shutdown_rx = handle_shutdown(&mut scheduler);
    let (oneshot_tx, oneshot_rx) = oneshot::channel();
    let oneshot_tx = Arc::new(Mutex::new(Some(oneshot_tx)));
    scheduler.shutdown_on_ctrl_c();
    scheduler.start().await?;

    // Initial run of the refresher
    scheduler
        .add(Job::new_one_shot_async(
            Duration::ZERO,
            move |_uuid, _l| {
                let oneshot_tx = oneshot_tx.clone();

                Box::pin(async move {
                    info!("Running refresh once");

                    if let Err(err) = refresh_tokens(comparison_duration).await {
                        error!("Error during refresh: {err:?}");
                    }

                    if let Err(err) = handle_shutdown_signal(&oneshot_tx) {
                        error!("Error while sending shutdown signal: {err}");
                    }
                })
            },
        )?)
        .await?;

    if args.scheduled {
        // Schedule periodic runs of the refresher
        scheduler
            .add(Job::new_repeated_async(
                CONFIG.refresh_interval,
                move |_uuid, _l| {
                    Box::pin(async move {
                        info!(
                            "Running refresh after {} seconds passed",
                            CONFIG.refresh_interval.as_secs()
                        );

                        if let Err(err) = refresh_tokens(comparison_duration).await {
                            error!("Error during refresh: {err:?}");
                        }
                    })
                },
            )?)
            .await?;
    }

    oneshot_rx.await?; // In each case, wait for the initial run to finish

    if args.scheduled {
        shutdown_rx.await.context("Improper shutdown")
    } else {
        Ok(())
    }
}

fn setup_tracing() {
    let default_log_level = if cfg!(debug_assertions) {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(default_log_level.into())
                .from_env_lossy(),
        )
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();
}

/// Add code to be run during/after shutdown
fn handle_shutdown(scheduler: &mut JobScheduler) -> Receiver<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    scheduler.set_shutdown_handler(Box::new(move || {
        let shutdown_tx = shutdown_tx.clone();
        Box::pin(async move {
            info!("Shutting down");
            if let Err(err) = handle_shutdown_signal(&shutdown_tx) {
                error!("Error during shutdown: {}", err);
            }
        })
    }));

    shutdown_rx
}

fn handle_shutdown_signal(shutdown_tx: &Mutex<Option<Sender<()>>>) -> Result<()> {
    let mut shutdown_tx_lock = shutdown_tx
        .lock()
        .map_err(|_| anyhow::anyhow!("Poisoned shutdown channel"))?;
    let shutdown_tx = shutdown_tx_lock
        .take()
        .context("Shutdown channel aready used")?;
    shutdown_tx
        .send(())
        .map_err(|()| anyhow::anyhow!("Cannot propagate shutdown signal"))
}

async fn refresh_tokens(refresh_interval: Option<Duration>) -> Result<()> {
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let jwks = retrieve_jwks(&http_client, &CONFIG.oidc.issuer).await?;

    let database = Database::new(&CONFIG.postgres).await?;

    let mut num_updated = 0;

    for ConnectorRefreshToken {
        id,
        refresh_token,
        expiry_date,
    } in database.get_refresh_tokens(refresh_interval).await?
    {
        match refresh_tokens_for_provider(
            &database,
            &http_client,
            jwks.clone(),
            ConnectorRefreshToken {
                id,
                refresh_token,
                expiry_date,
            },
        )
        .await
        {
            Ok(()) => {
                num_updated += 1;
                debug!(provider = ?id, "Refreshed token");
            }
            Err(err) => {
                error!(provider = ?id, "Error refreshing token: {err:?}");
            }
        }
    }

    info!("Updated {num_updated} refresh tokens");

    Ok(())
}

async fn refresh_tokens_for_provider(
    database: &Database,
    http_client: &reqwest::Client,
    jwks: JsonWebKeySet<CoreJsonWebKey>,
    ConnectorRefreshToken {
        id,
        refresh_token,
        expiry_date: _,
    }: ConnectorRefreshToken,
) -> Result<()> {
    let token_response = retrieve_access_and_refresh_token(
        http_client,
        &CONFIG.oidc,
        jwks.clone(),
        &RefreshToken::new(refresh_token),
    )
    .await?;

    let now = time::OffsetDateTime::now_utc();
    let expiry_duration = time::Duration::seconds(token_response.refresh_expires_in as i64);
    let expiry_date = now.saturating_add(expiry_duration);

    let connector_refresh_token = ConnectorRefreshToken {
        id,
        refresh_token: token_response.refresh_token.into_secret(),
        expiry_date,
    };

    database.update_refresh_token(connector_refresh_token).await
}
