use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use url::Url;

use crate::whitelist::{TierList, WhitelistConfig};

const DEFAULT_MUMBLE_PORT: u16 = 64738;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub public_url: String,
    pub public_domain: String,
    pub log_filter: String,
    pub cluster_name: String,
    pub eve_client_id: String,
    pub eve_client_secret: String,
    pub esi_compatibility_date: String,
    pub jwt_validate_exp: bool,
    pub jwt_max_age_seconds: Option<u64>,
    pub mumble_auth_token: String,
    pub mumble_url: Option<String>,
    pub mumble_servers: Vec<MumbleServer>,
    pub whitelist: WhitelistConfig,
    pub cache_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MumbleServer {
    pub host: String,
    #[serde(default = "default_mumble_port")]
    pub port: u16,
    #[serde(default)]
    pub name: Option<String>,
}

fn default_mumble_port() -> u16 {
    DEFAULT_MUMBLE_PORT
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    public_url: String,
    cluster_name: String,
    #[serde(default = "default_bind_addr")]
    bind_addr: String,
    #[serde(default = "default_log_filter")]
    log_filter: String,
    eve: EveSection,
    #[serde(default)]
    esi: EsiSection,
    #[serde(default)]
    jwt: JwtSection,
    mumble: MumbleSection,
    #[serde(default)]
    servers: Vec<MumbleServer>,
    whitelist: Option<TierList>,
    #[serde(default)]
    groups: BTreeMap<String, TierList>,
    #[serde(default)]
    cache: CacheSection,
}

#[derive(Debug, Deserialize)]
struct EveSection {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize)]
struct EsiSection {
    #[serde(default = "default_esi_date")]
    compatibility_date: String,
}

impl Default for EsiSection {
    fn default() -> Self {
        Self {
            compatibility_date: default_esi_date(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtSection {
    #[serde(default = "default_validate_exp")]
    validate_exp: bool,
    #[serde(default)]
    max_age_seconds: Option<u64>,
}

impl Default for JwtSection {
    fn default() -> Self {
        Self {
            validate_exp: default_validate_exp(),
            max_age_seconds: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct MumbleSection {
    auth_token: String,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CacheSection {
    #[serde(default = "default_cache_path")]
    path: String,
}

impl Default for CacheSection {
    fn default() -> Self {
        Self {
            path: default_cache_path(),
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_log_filter() -> String {
    "info".into()
}
fn default_esi_date() -> String {
    "2026-05-06".into()
}
fn default_validate_exp() -> bool {
    true
}
fn default_cache_path() -> String {
    "./cache.json".into()
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let toml_text = std::fs::read_to_string(path)
            .with_context(|| format!("read config file {}", path.display()))?;
        let raw: ConfigFile =
            toml::from_str(&toml_text).context("parse config toml")?;

        let public_url = raw.public_url.trim_end_matches('/').to_string();
        let public_domain = Url::parse(&public_url)
            .context("public_url is not a valid URL")?
            .host_str()
            .ok_or_else(|| anyhow!("public_url has no host"))?
            .to_string();

        if raw.cluster_name.trim().is_empty() {
            return Err(anyhow!("cluster_name must not be empty"));
        }
        if raw.mumble.auth_token.trim().is_empty() {
            return Err(anyhow!("mumble.auth_token must not be empty"));
        }
        if raw.servers.is_empty() {
            return Err(anyhow!(
                "config must define at least one [[servers]] entry"
            ));
        }
        for s in &raw.servers {
            if s.host.trim().is_empty() {
                return Err(anyhow!("[[servers]].host must not be empty"));
            }
        }

        Ok(Self {
            bind_addr: raw.bind_addr,
            public_url,
            public_domain,
            log_filter: raw.log_filter,
            cluster_name: raw.cluster_name,
            eve_client_id: raw.eve.client_id,
            eve_client_secret: raw.eve.client_secret,
            esi_compatibility_date: raw.esi.compatibility_date,
            jwt_validate_exp: raw.jwt.validate_exp,
            jwt_max_age_seconds: raw.jwt.max_age_seconds,
            mumble_auth_token: raw.mumble.auth_token,
            mumble_url: raw.mumble.url,
            mumble_servers: raw.servers,
            whitelist: WhitelistConfig {
                whitelist: raw.whitelist,
                groups: raw.groups,
            },
            cache_path: PathBuf::from(raw.cache.path),
        })
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/callback", self.public_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn example_config_parses() {
        let cfg =
            Config::from_file(Path::new("config.example.toml")).expect("example config");
        assert!(!cfg.mumble_servers.is_empty());
        assert!(!cfg.mumble_auth_token.is_empty());
        assert_eq!(cfg.public_domain, "localhost");
        assert!(cfg.jwt_validate_exp);
    }

    #[test]
    fn missing_whitelist_allows_everyone() {
        let config = r#"
public_url = "http://localhost:8080"
cluster_name = "Test"

[eve]
client_id = "client-id"
client_secret = "client-secret"

[mumble]
auth_token = "token"

[[servers]]
host = "mumble.example.com"
"#;
        let path = std::env::temp_dir().join(format!(
            "mumble-auth-3p-config-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, config).expect("write config");
        let cfg = Config::from_file(&path).expect("config without whitelist");
        std::fs::remove_file(&path).expect("remove config");

        assert!(cfg.whitelist.whitelist.is_none());
    }
}
