use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use stellar_strkey::{ed25519, Strkey};
use tokio::sync::Mutex;

use crate::{
    config::Config,
    error::AppError,
    horizon::HorizonCluster,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub global_limiter: Arc<RateLimiter>,
    pub horizon: Arc<HorizonCluster>,
    pub quota_ledger: Arc<Mutex<Vec<SponsoredTransactionRecord>>>,
    pub signer_pool: Arc<SignerPool>,
    pub transaction_store: Arc<Mutex<HashMap<String, TransactionRecord>>>,
    pub api_key_limiter: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

#[derive(Clone)]
pub struct ApiKeyConfig {
    pub daily_quota_stroops: i64,
    pub key: &'static str,
    pub max_requests: u32,
    pub name: &'static str,
    pub tenant_id: &'static str,
    pub tier: &'static str,
    pub window_ms: u64,
}

pub const API_KEYS: [ApiKeyConfig; 2] = [
    ApiKeyConfig {
        daily_quota_stroops: 200,
        key: "fluid-free-demo-key",
        max_requests: 2,
        name: "Demo Free dApp",
        tenant_id: "tenant-demo-free",
        tier: "free",
        window_ms: 60_000,
    },
    ApiKeyConfig {
        daily_quota_stroops: 2_000,
        key: "fluid-pro-demo-key",
        max_requests: 5,
        name: "Demo Pro dApp",
        tenant_id: "tenant-demo-pro",
        tier: "pro",
        window_ms: 60_000,
    },
];

#[derive(Clone)]
pub struct SignerAccount {
    pub active: bool,
    pub public_key: String,
    pub public_key_bytes: [u8; 32],
    pub secret: String,
    pub total_uses: u64,
    pub in_flight: u32,
}

#[derive(Clone)]
pub struct SignerPool {
    inner: Arc<Mutex<Vec<SignerAccount>>>,
}

pub struct SignerLease {
    pub account: SignerAccount,
    index: usize,
    pool: Arc<Mutex<Vec<SignerAccount>>>,
}

#[derive(Clone, Serialize)]
pub struct HealthFeePayer {
    pub balance: Option<String>,
    pub in_flight: u32,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub sequence_number: Option<String>,
    pub status: &'static str,
    pub total_uses: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub created_at: String,
    pub hash: String,
    pub status: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct SponsoredTransactionRecord {
    pub created_at_ms: u128,
    pub fee_stroops: i64,
    pub tenant_id: String,
}

#[derive(Clone)]
pub struct RateLimiter {
    entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    max: u32,
    window_ms: u64,
}

#[derive(Clone)]
pub struct RateLimitEntry {
    pub count: u32,
    pub reset_time_ms: u128,
}

pub struct RateLimitResult {
    pub limit: u32,
    pub remaining: u32,
    pub reset_time_epoch_seconds: u64,
}

impl AppState {
    pub fn new(config: Config, secrets: &[String]) -> Result<Self, AppError> {
        let config = Arc::new(config);
        Ok(Self {
            api_key_limiter: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::clone(&config),
            global_limiter: Arc::new(RateLimiter::new(
                config.global_rate_limit_max,
                config.global_rate_limit_window_ms,
            )),
            horizon: Arc::new(HorizonCluster::new(
                &config.horizon_urls,
                config.horizon_selection_strategy,
            )),
            quota_ledger: Arc::new(Mutex::new(Vec::new())),
            signer_pool: Arc::new(SignerPool::new(secrets)?),
            transaction_store: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

impl SignerPool {
    pub fn new(secrets: &[String]) -> Result<Self, AppError> {
        if secrets.is_empty() {
            return Err(AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "SignerPool requires at least one account",
            ));
        }

        let mut accounts = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let (public_key_bytes, public_key) = decode_secret(secret)?;
            accounts.push(SignerAccount {
                active: true,
                public_key,
                public_key_bytes,
                secret: secret.clone(),
                total_uses: 0,
                in_flight: 0,
            });
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(accounts)),
        })
    }

    pub async fn acquire(&self) -> Result<SignerLease, AppError> {
        let mut guard = self.inner.lock().await;
        let (index, account) = guard
            .iter_mut()
            .enumerate()
            .filter(|(_, account)| account.active)
            .min_by_key(|(_, account)| (account.in_flight, account.total_uses))
            .ok_or_else(|| {
                AppError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "INTERNAL_ERROR",
                    "No active signer accounts are available",
                )
            })?;

        account.in_flight += 1;
        account.total_uses += 1;

        Ok(SignerLease {
            account: account.clone(),
            index,
            pool: Arc::clone(&self.inner),
        })
    }

    pub async fn snapshot(&self) -> Vec<HealthFeePayer> {
        let guard = self.inner.lock().await;
        guard
            .iter()
            .map(|account| HealthFeePayer {
                balance: None,
                in_flight: account.in_flight,
                public_key: account.public_key.clone(),
                sequence_number: None,
                status: if account.active { "active" } else { "inactive" },
                total_uses: account.total_uses,
            })
            .collect()
    }
}

impl SignerLease {
    pub async fn release(self) {
        let mut guard = self.pool.lock().await;
        if let Some(account) = guard.get_mut(self.index) {
            account.in_flight = account.in_flight.saturating_sub(1);
        }
    }
}

impl RateLimiter {
    pub fn new(max: u32, window_ms: u64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            max,
            window_ms,
        }
    }

    pub async fn check(&self, key: &str) -> Result<RateLimitResult, AppError> {
        let mut guard = self.entries.lock().await;
        let now_ms = now_ms();
        let entry = guard.entry(key.to_string()).or_insert_with(|| RateLimitEntry {
            count: 0,
            reset_time_ms: now_ms + u128::from(self.window_ms),
        });

        if now_ms >= entry.reset_time_ms {
            entry.count = 0;
            entry.reset_time_ms = now_ms + u128::from(self.window_ms);
        }

        if entry.count >= self.max {
            return Err(AppError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Too many requests from this IP, please try again later.",
            ));
        }

        entry.count += 1;

        Ok(RateLimitResult {
            limit: self.max,
            remaining: self.max.saturating_sub(entry.count),
            reset_time_epoch_seconds: (entry.reset_time_ms / 1_000) as u64,
        })
    }
}

fn decode_secret(secret: &str) -> Result<([u8; 32], String), AppError> {
    let secret = match Strkey::from_string(secret).map_err(|error| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to parse fee payer secret: {error}"),
        )
    })? {
        Strkey::PrivateKeyEd25519(private_key) => private_key,
        _ => {
            return Err(AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Expected a Stellar ed25519 private key",
            ))
        }
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key = Strkey::PublicKeyEd25519(ed25519::PublicKey(public_key_bytes)).to_string();

    Ok((public_key_bytes, public_key))
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

pub fn iso_now() -> String {
    format!("{}", now_ms())
}

pub fn utc_day_start_ms() -> u128 {
    let now = now_ms() / 1_000;
    let days = now / 86_400;
    u128::from(days * 86_400 * 1_000)
}
