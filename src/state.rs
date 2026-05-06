use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use crate::affiliation_cache::AffiliationCache;
use crate::config::Config;
use crate::eve::{EsiClient, EveSso, JwtPolicy};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub sso: Arc<EveSso>,
    pub esi: Arc<EsiClient>,
    pub pkce: Arc<DashMap<String, PkceEntry>>,
    pub affiliation_cache: Arc<AffiliationCache>,
}

pub struct PkceEntry {
    pub verifier: String,
    pub expires_at: Instant,
}

impl AppState {
    pub async fn new(cfg: Config) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .build()?;
        let sso = EveSso::new(
            http.clone(),
            cfg.eve_client_id.clone(),
            cfg.eve_client_secret.clone(),
            JwtPolicy {
                validate_exp: cfg.jwt_validate_exp,
                max_age_seconds: cfg.jwt_max_age_seconds,
            },
        );
        let esi = Arc::new(EsiClient::new(http, cfg.esi_compatibility_date.clone()));
        let affiliation_cache = Arc::new(AffiliationCache::load(
            cfg.cache_path.clone(),
            Arc::clone(&esi),
        )?);
        Ok(Self {
            cfg: Arc::new(cfg),
            sso: Arc::new(sso),
            esi,
            pkce: Arc::new(DashMap::new()),
            affiliation_cache,
        })
    }
}
