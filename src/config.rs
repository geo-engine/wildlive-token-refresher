use config::{Environment, File};
use serde::Deserialize;
use std::{ops::Mul, path::Path, sync::LazyLock, time::Duration};
use url::Url;

pub static CONFIG: LazyLock<Config> =
    LazyLock::new(|| get_config().expect("config cannot be loaded"));

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub refresh_interval: Duration,
    pub refresh_buffer_pct: RefreshBuffer,
    pub oidc: Oidc,
    pub postgres: Postgres,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct RefreshBuffer(u16);

impl RefreshBuffer {
    pub fn factor(self) -> f64 {
        1. + (f64::from(self.0) / 100.)
    }
}

impl Mul<Duration> for RefreshBuffer {
    type Output = Duration;

    fn mul(self, rhs: Duration) -> Self::Output {
        let secs = rhs.as_secs_f64();
        let buffered_secs = secs * self.factor();
        Duration::from_secs_f64(buffered_secs)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oidc {
    pub issuer: Url,
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Postgres {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub schema: String,
    pub user: String,
    pub password: String,
}

impl Postgres {
    pub fn pg_config(&self) -> tokio_postgres::Config {
        let mut config = tokio_postgres::Config::new();
        config
            .user(&self.user)
            .password(&self.password)
            .host(&self.host)
            .dbname(&self.database)
            .port(self.port)
            .options(format!("-c search_path={}", self.schema));
        config
    }
}

fn get_config() -> anyhow::Result<Config> {
    let mut builder = config::Config::builder();

    builder = builder.add_source(config::File::from_str(
        include_str!("../conf/default.toml"),
        config::FileFormat::Toml,
    ));

    let settings_file = Path::new("Settings.toml");
    if settings_file.exists() {
        builder = builder.add_source(File::from(settings_file));
    }

    // Override config with environment variables that start with `WILDLIVETOKENREFRESHER__`,
    // e.g. `WILDLIVETOKENREFRESHER__POSTGRES__PASSWORD=secret`
    // Note: Since variables contain underscores, we need to use something different
    // for separating groups, for instance double underscores `__`
    builder =
        builder.add_source(Environment::with_prefix("wildlivetokenrefresher").separator("__"));

    Ok(builder.build()?.try_deserialize()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds_a_buffer_to_a_duration() {
        let duration = Duration::from_secs(100);
        let buffer = RefreshBuffer(20); // 20%

        let buffered_duration = buffer * duration;

        assert_eq!(buffered_duration.as_secs(), 120);
    }
}
