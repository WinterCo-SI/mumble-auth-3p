use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct JwtPolicy {
    pub validate_exp: bool,
    pub max_age_seconds: Option<u64>,
}

const OIDC_DISCOVERY_URL: &str =
    "https://login.eveonline.com/.well-known/openid-configuration";
const ESI_BASE: &str = "https://esi.evetech.net";
const REFRESH_TTL: Duration = Duration::from_secs(3600);
const AFFILIATION_TTL: Duration = Duration::from_secs(3600);
const ALLOWED_ISSUERS: &[&str] = &["login.eveonline.com", "https://login.eveonline.com"];

// ---- OIDC discovery + JWKS ------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub issuer: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Clone)]
struct CacheInner {
    discovery: OidcDiscovery,
    keys: HashMap<String, Arc<DecodingKey>>,
    fetched_at: Instant,
}

// ---- EVE SSO client -------------------------------------------------------

pub struct EveSso {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    policy: JwtPolicy,
    cache: RwLock<Option<CacheInner>>,
}

impl EveSso {
    pub fn new(
        http: reqwest::Client,
        client_id: String,
        client_secret: String,
        policy: JwtPolicy,
    ) -> Self {
        Self {
            http,
            client_id,
            client_secret,
            policy,
            cache: RwLock::new(None),
        }
    }

    pub async fn discovery(&self) -> Result<OidcDiscovery, AppError> {
        Ok(self.cache().await?.discovery)
    }

    pub async fn verify_access_token(&self, jwt: &str) -> Result<EveClaims, AppError> {
        let header = decode_header(jwt)
            .map_err(|e| AppError::Unauthorized(format!("invalid jwt header: {e}")))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("jwt missing kid".into()))?
            .to_string();

        let alg = match header.alg {
            Algorithm::RS256 | Algorithm::ES256 => header.alg,
            other => {
                return Err(AppError::Unauthorized(format!(
                    "unsupported jwt alg {:?}",
                    other
                )))
            }
        };

        let key = self.key_for_kid(&kid).await?;

        let mut validation = Validation::new(alg);
        validation.set_issuer(ALLOWED_ISSUERS);
        validation.set_audience(&[self.client_id.as_str()]);
        validation.validate_exp = self.policy.validate_exp;
        if !self.policy.validate_exp {
            // Don't reject for missing/invalid exp once exp validation is off.
            validation.required_spec_claims.remove("exp");
        }

        let data = decode::<EveClaims>(jwt, &key, &validation)
            .map_err(|e| AppError::Unauthorized(format!("jwt verify failed: {e}")))?;

        if let Some(max_age) = self.policy.max_age_seconds {
            let iat = data.claims.iat.ok_or_else(|| {
                AppError::Unauthorized(
                    "jwt missing iat (required by JWT_MAX_AGE_SECONDS)".into(),
                )
            })?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AppError::Internal("system clock before unix epoch".into()))?
                .as_secs();
            if now > iat && now - iat > max_age {
                return Err(AppError::Unauthorized(format!(
                    "jwt issued {}s ago, exceeds JWT_MAX_AGE_SECONDS={}",
                    now - iat,
                    max_age
                )));
            }
        }

        Ok(data.claims)
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, AppError> {
        let token_endpoint = self.discovery().await?.token_endpoint;
        let res = self
            .http
            .post(&token_endpoint)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(AppError::Upstream(format!(
                "token endpoint returned {status}: {body}"
            )));
        }
        Ok(res.json().await?)
    }

    async fn key_for_kid(&self, kid: &str) -> Result<Arc<DecodingKey>, AppError> {
        if let Some(k) = self.cache().await?.keys.get(kid).cloned() {
            return Ok(k);
        }
        // Unknown kid — could be a rotated key. Force a refresh once.
        let new = self.refresh_now().await?;
        new.keys.get(kid).cloned().ok_or_else(|| {
            AppError::Unauthorized(format!("unknown jwt kid {kid}"))
        })
    }

    async fn cache(&self) -> Result<CacheInner, AppError> {
        if let Some(c) = self.cache.read().await.clone() {
            if c.fetched_at.elapsed() < REFRESH_TTL {
                return Ok(c);
            }
        }
        self.refresh_now().await
    }

    async fn refresh_now(&self) -> Result<CacheInner, AppError> {
        let mut w = self.cache.write().await;
        if let Some(c) = w.clone() {
            if c.fetched_at.elapsed() < REFRESH_TTL {
                return Ok(c);
            }
        }
        let new = fetch_oidc_and_jwks(&self.http).await?;
        *w = Some(new.clone());
        Ok(new)
    }
}

async fn fetch_oidc_and_jwks(http: &reqwest::Client) -> Result<CacheInner, AppError> {
    let discovery: OidcDiscovery = http
        .get(OIDC_DISCOVERY_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let jwks: Jwks = http
        .get(&discovery.jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut keys = HashMap::with_capacity(jwks.keys.len());
    for k in jwks.keys {
        if let Some(dk) = jwk_to_decoding_key(&k) {
            keys.insert(k.kid, Arc::new(dk));
        } else {
            tracing::warn!(kid = %k.kid, kty = %k.kty, "skipping unsupported JWK");
        }
    }
    Ok(CacheInner {
        discovery,
        keys,
        fetched_at: Instant::now(),
    })
}

fn jwk_to_decoding_key(k: &Jwk) -> Option<DecodingKey> {
    match k.kty.as_str() {
        "RSA" => {
            let n = k.n.as_deref()?;
            let e = k.e.as_deref()?;
            DecodingKey::from_rsa_components(n, e).ok()
        }
        "EC" => {
            let x = k.x.as_deref()?;
            let y = k.y.as_deref()?;
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

// ---- Claims & token response ---------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EveClaims {
    pub sub: String,
    pub name: String,
    #[serde(default)]
    pub exp: Option<u64>,
    pub iss: String,
    #[serde(default)]
    pub iat: Option<u64>,
}

impl EveClaims {
    pub fn character_id(&self) -> Result<u64, AppError> {
        let id = self
            .sub
            .strip_prefix("CHARACTER:EVE:")
            .ok_or_else(|| {
                AppError::Unauthorized(format!(
                    "sub not in CHARACTER:EVE:<id> form: {}",
                    self.sub
                ))
            })?;
        id.parse::<u64>()
            .map_err(|e| AppError::Unauthorized(format!("sub id parse: {e}")))
    }
}

// ---- ESI client ----------------------------------------------------------

pub struct EsiClient {
    http: reqwest::Client,
    compatibility_date: String,
    affiliations: RwLock<HashMap<u64, (Affiliation, Instant)>>,
}

impl EsiClient {
    pub fn new(http: reqwest::Client, compatibility_date: String) -> Self {
        Self {
            http,
            compatibility_date,
            affiliations: RwLock::new(HashMap::new()),
        }
    }

    pub async fn affiliation(&self, char_id: u64) -> Result<Affiliation, AppError> {
        {
            let cache = self.affiliations.read().await;
            if let Some((aff, fetched_at)) = cache.get(&char_id) {
                if fetched_at.elapsed() < AFFILIATION_TTL {
                    return Ok(aff.clone());
                }
            }
        }

        let url = format!("{ESI_BASE}/characters/affiliation/");
        let res = self
            .http
            .post(url)
            .header("X-Compatibility-Date", &self.compatibility_date)
            .json(&[char_id])
            .send()
            .await?;
        let list: Vec<Affiliation> = esi_json(res, "characters/affiliation").await?;
        let aff = list
            .into_iter()
            .next()
            .ok_or_else(|| AppError::Upstream("empty affiliation response".into()))?;
        self.affiliations
            .write()
            .await
            .insert(char_id, (aff.clone(), Instant::now()));
        Ok(aff)
    }

    pub async fn alliance(&self, alliance_id: u64) -> Result<AllianceInfo, AppError> {
        let url = format!("{ESI_BASE}/alliances/{alliance_id}/");
        let res = self
            .http
            .get(url)
            .header("X-Compatibility-Date", &self.compatibility_date)
            .send()
            .await?;
        esi_json(res, "alliances/{id}").await
    }

    pub async fn corporation(&self, corp_id: u64) -> Result<CorporationInfo, AppError> {
        let url = format!("{ESI_BASE}/corporations/{corp_id}/");
        let res = self
            .http
            .get(url)
            .header("X-Compatibility-Date", &self.compatibility_date)
            .send()
            .await?;
        esi_json(res, "corporations/{id}").await
    }
}

async fn esi_json<T: serde::de::DeserializeOwned>(
    res: reqwest::Response,
    endpoint: &str,
) -> Result<T, AppError> {
    let status = res.status();
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(AppError::Upstream(format!(
            "ESI {endpoint} returned {status}: {body}"
        )));
    }
    Ok(res.json().await?)
}

#[derive(Debug, Deserialize, Clone)]
pub struct Affiliation {
    pub character_id: u64,
    pub corporation_id: u64,
    #[serde(default)]
    pub alliance_id: Option<u64>,
    #[serde(default)]
    pub faction_id: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AllianceInfo {
    pub name: String,
    pub ticker: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorporationInfo {
    pub name: String,
    pub ticker: String,
    #[serde(default)]
    pub alliance_id: Option<u64>,
}
