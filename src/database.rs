use std::time::Duration;

use anyhow::Result;
use indoc::indoc;
use tokio_postgres::{Client, NoTls};
use tracing::error;
use uuid::Uuid;

use crate::config::Postgres;

pub struct Database {
    client: Client,
    _handle: tokio::task::JoinHandle<()>,
}

impl Database {
    pub async fn new(config: &Postgres) -> Result<Self> {
        let (client, connection) = config.pg_config().connect(NoTls).await?;

        let handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("connection error: {}", e);
            }
        });

        Ok(Self {
            client,
            _handle: handle,
        })
    }

    pub async fn get_refresh_tokens(
        &self,
        comparison_duration: Duration,
    ) -> Result<Vec<IdTokenPair>> {
        let now = time::OffsetDateTime::now_utc();
        let comparison_duration = time::Duration::try_from(comparison_duration)?;
        let now_plus_duration = now.saturating_add(comparison_duration);

        let results = self
            .client
            .query_typed(
                indoc! {"
                SELECT
                    id,
                    (((definition).wildlive_data_connector_definition).auth).refresh_token AS refresh_token
                FROM
                    layer_providers
                WHERE
                    type_name = 'WildLIVE!'
                    AND
                    (((definition).wildlive_data_connector_definition).auth).refresh_token IS NOT NULL
                    AND
                    $1 >= (((definition).wildlive_data_connector_definition).auth).expiry_date
                "},
                &[
                    (&now_plus_duration, tokio_postgres::types::Type::TIMESTAMPTZ),
                ],
            )
            .await?;

        results
            .iter()
            .map(|row| {
                Ok(IdTokenPair {
                    id: row.try_get("id")?,
                    refresh_token: row.try_get("refresh_token")?,
                })
            })
            .collect()
    }

    // TODO: bulk insert multiple tokens at once
    pub async fn update_refresh_token(
        &self,
        IdTokenPair { id, refresh_token }: IdTokenPair,
    ) -> Result<()> {
        self.client
            .execute(
                indoc! {"
                UPDATE
                    layer_providers
                SET
                    definition.wildlive_data_connector_definition.auth.refresh_token = $2
                WHERE
                    id = $1
                "},
                &[&id, &refresh_token],
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct IdTokenPair {
    pub id: Uuid,
    pub refresh_token: String,
}
