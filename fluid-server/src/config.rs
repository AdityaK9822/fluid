use crate::error::AppError;
use axum::http::StatusCode;

#[derive(Clone, Copy)]
pub enum HorizonSelectionStrategy {
    Priority,
    RoundRobin,
}

#[derive(Clone)]
pub struct Config {
    pub allowed_origins: Vec<String>,
    pub base_fee: i64,
    pub fee_multiplier: f64,
    pub global_rate_limit_max: u32,
    pub global_rate_limit_window_ms: u64,
    pub horizon_selection_strategy: HorizonSelectionStrategy,
    pub horizon_urls: Vec<String>,
    pub network_passphrase: String,
    pub port: u16,
}

pub fn load_config() -> Result<(Config, Vec<String>), AppError> {
    let secrets = parse_csv_env("FLUID_FEE_PAYER_SECRET").ok_or_else(|| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "FLUID_FEE_PAYER_SECRET environment variable is required",
        )
    })?;

    let allowed_origins = parse_csv_env("FLUID_ALLOWED_ORIGINS").unwrap_or_default();
    let base_fee = env_parse("FLUID_BASE_FEE", 100_i64);
    let fee_multiplier = env_parse("FLUID_FEE_MULTIPLIER", 2.0_f64);
    let global_rate_limit_max = env_parse("FLUID_RATE_LIMIT_MAX", 5_u32);
    let global_rate_limit_window_ms = env_parse("FLUID_RATE_LIMIT_WINDOW_MS", 60_000_u64);
    let configured_horizon_urls = parse_csv_env("STELLAR_HORIZON_URLS").unwrap_or_default();
    let legacy_horizon_url = std::env::var("STELLAR_HORIZON_URL").ok();
    let horizon_urls = if configured_horizon_urls.is_empty() {
        legacy_horizon_url
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect()
    } else {
        configured_horizon_urls
    };
    let horizon_selection_strategy = match std::env::var("FLUID_HORIZON_SELECTION")
        .unwrap_or_else(|_| "priority".to_string())
        .as_str()
    {
        "round_robin" => HorizonSelectionStrategy::RoundRobin,
        _ => HorizonSelectionStrategy::Priority,
    };
    let network_passphrase = std::env::var("STELLAR_NETWORK_PASSPHRASE")
        .unwrap_or_else(|_| "Test SDF Network ; September 2015".to_string());
    let port = env_parse("PORT", 3000_u16);

    Ok((
        Config {
            allowed_origins,
            base_fee,
            fee_multiplier,
            global_rate_limit_max,
            global_rate_limit_window_ms,
            horizon_selection_strategy,
            horizon_urls,
            network_passphrase,
            port,
        },
        secrets,
    ))
}

fn env_parse<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_csv_env(key: &str) -> Option<Vec<String>> {
    std::env::var(key).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}
