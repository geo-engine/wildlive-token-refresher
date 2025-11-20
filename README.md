# WildLIVE Token Refresher

A process that refreshes short-lived OIDC refresh tokens for the WildLIVE API.

## Usage

```rust
cargo run
```

### Flags

- `--force`: Refresh all tokens immediately, regardless of their current validity.
- `--scheduled`: Run the token refresher in a scheduled manner, refreshing tokens at regular intervals defined in the settings.

## Settings

Create either a `Settings.toml` file or override settings using environment variables.

### Settings.toml

You can find the defaults in [conf/default.toml](conf/default.toml).

```toml
refresh_interval = { secs = 100 }

[oidc]
client_secret = "<SECRET>"

```

### Environment Variables

You can override settings using all variables from [conf/default.toml](conf/default.toml).
For instance, you can set the following environment variables:

- `WILDLIVETOKENREFRESHER__REFRESH_INTERVAL__SECS`: Interval in seconds between token refreshes.
- `WILDLIVETOKENREFRESHER__OIDC__CLIENT_SECRET`: OIDC client secret.
