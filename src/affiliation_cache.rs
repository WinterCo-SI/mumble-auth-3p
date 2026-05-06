use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::error::AppError;
use crate::eve::EsiClient;

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    #[serde(default)]
    alliances: HashMap<u64, String>,
    #[serde(default)]
    corporations: HashMap<u64, String>,
}

/// Persistent on-disk cache of alliance/corporation tickers.
///
/// Entries are immutable once written: a given ID always maps to the ticker
/// it had at first sight. Renames are rare in practice and tolerating a
/// slightly out-of-date ticker is preferable to the complexity of refresh.
/// Entries are populated lazily as users log in.
pub struct AffiliationCache {
    path: PathBuf,
    alliances: RwLock<HashMap<u64, String>>,
    corporations: RwLock<HashMap<u64, String>>,
    esi: Arc<EsiClient>,
    save_lock: Mutex<()>,
}

impl AffiliationCache {
    pub fn load(path: PathBuf, esi: Arc<EsiClient>) -> anyhow::Result<Self> {
        let snapshot = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Snapshot>(&bytes)
                .with_context(|| format!("parse cache file {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Snapshot::default(),
            Err(e) => return Err(anyhow!("read cache file {}: {e}", path.display())),
        };
        tracing::info!(
            alliances = snapshot.alliances.len(),
            corporations = snapshot.corporations.len(),
            cache = %path.display(),
            "loaded affiliation cache"
        );
        Ok(Self {
            path,
            alliances: RwLock::new(snapshot.alliances),
            corporations: RwLock::new(snapshot.corporations),
            esi,
            save_lock: Mutex::new(()),
        })
    }

    pub async fn alliance_ticker(&self, id: u64) -> Result<String, AppError> {
        if let Some(ticker) = self.alliances.read().await.get(&id).cloned() {
            return Ok(ticker);
        }
        let info = self.esi.alliance(id).await?;
        let ticker = info.ticker.clone();
        self.alliances.write().await.insert(id, info.ticker);
        if let Err(e) = self.persist().await {
            tracing::warn!(error = %e, "persist affiliation cache after alliance fetch failed");
        }
        Ok(ticker)
    }

    pub async fn corp_ticker(&self, id: u64) -> Result<String, AppError> {
        if let Some(ticker) = self.corporations.read().await.get(&id).cloned() {
            return Ok(ticker);
        }
        let info = self.esi.corporation(id).await?;
        let ticker = info.ticker.clone();
        self.corporations.write().await.insert(id, info.ticker);
        if let Err(e) = self.persist().await {
            tracing::warn!(error = %e, "persist affiliation cache after corp fetch failed");
        }
        Ok(ticker)
    }

    async fn persist(&self) -> Result<(), AppError> {
        let _guard = self.save_lock.lock().await;
        let snapshot = Snapshot {
            alliances: self.alliances.read().await.clone(),
            corporations: self.corporations.read().await.clone(),
        };
        let data = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| AppError::Internal(format!("serialize cache: {e}")))?;
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, &data)
            .await
            .map_err(|e| AppError::Internal(format!("write cache tmp: {e}")))?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .map_err(|e| AppError::Internal(format!("rename cache file: {e}")))?;
        Ok(())
    }
}
