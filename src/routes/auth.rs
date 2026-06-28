use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{header::AUTHORIZATION, request::Parts},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;
use crate::whitelist::decide;

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: u64,
    pub display_name: String,
    pub groups: Vec<String>,
}

/// Marker extractor that succeeds when a valid `Authorization: Bearer <token>`
/// header is present. Implemented as `FromRequestParts` so it runs before the
/// JSON body extractor — a missing/wrong token returns 401 without leaking
/// JSON parse errors back to unauthenticated callers.
pub struct BearerAuth;

#[async_trait]
impl FromRequestParts<AppState> for BearerAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?
            .to_str()
            .map_err(|_| AppError::Unauthorized("invalid Authorization header".into()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("expected Bearer scheme".into()))?;
        if !ct_eq(token.as_bytes(), state.cfg.mumble_auth_token.as_bytes()) {
            return Err(AppError::Unauthorized("invalid bearer token".into()));
        }
        Ok(BearerAuth)
    }
}

pub async fn handle(
    _bearer: BearerAuth,
    State(s): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let username = req.username.clone();
    match run_auth(&s, req).await {
        Ok(resp) => {
            tracing::info!(
                user_id = resp.user_id,
                display_name = %resp.display_name,
                groups = ?resp.groups,
                "auth granted"
            );
            Ok(Json(resp))
        }
        Err(e) => {
            tracing::warn!(username = %username, error = %e, "auth denied");
            Err(e)
        }
    }
}

async fn run_auth(s: &AppState, req: AuthRequest) -> Result<AuthResponse, AppError> {
    let claims = s.sso.verify_access_token(&req.password).await?;
    let char_id = claims.character_id()?;

    // Mumble username is "<char_id>@<public_domain>". Strip the suffix and
    // parse the numeric prefix; the JWT remains the source of truth for
    // identity, so the suffix is treated as informational.
    let id_str = req
        .username
        .split_once('@')
        .map(|(left, _)| left)
        .unwrap_or(&req.username);
    let provided: u64 = id_str
        .parse()
        .map_err(|_| AppError::BadRequest("username must be numeric character_id".into()))?;
    if provided != char_id {
        return Err(AppError::Unauthorized(
            "username does not match jwt sub".into(),
        ));
    }

    let aff = s.esi.affiliation(char_id).await?;
    let decision = decide(
        char_id,
        aff.corporation_id,
        aff.alliance_id,
        &s.cfg.whitelist,
    );
    if !decision.admitted {
        return Err(AppError::Forbidden("not in whitelist".into()));
    }

    let corp_ticker = match s.affiliation_cache.corp_ticker(aff.corporation_id).await {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::warn!(corporation_id = aff.corporation_id, error = %e, "corp ticker lookup failed");
            None
        }
    };
    let alliance_ticker = match aff.alliance_id {
        Some(alliance_id) => match s.affiliation_cache.alliance_ticker(alliance_id).await {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(alliance_id, error = %e, "alliance ticker lookup failed");
                None
            }
        },
        None => None,
    };
    let display_name = build_display_name(
        alliance_ticker.as_deref(),
        corp_ticker.as_deref(),
        &claims.name,
    );
    let mut groups = decision.groups;
    groups.extend(build_ticker_groups(
        alliance_ticker.as_deref(),
        corp_ticker.as_deref(),
    ));

    Ok(AuthResponse {
        user_id: char_id,
        display_name,
        groups,
    })
}

fn build_display_name(
    alliance_ticker: Option<&str>,
    corp_ticker: Option<&str>,
    character_name: &str,
) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(3);
    if let Some(t) = alliance_ticker.filter(|s| !s.is_empty()) {
        parts.push(t);
    }
    if let Some(t) = corp_ticker.filter(|s| !s.is_empty()) {
        parts.push(t);
    }
    parts.push(character_name);
    parts.join("-")
}

fn build_ticker_groups(alliance_ticker: Option<&str>, corp_ticker: Option<&str>) -> Vec<String> {
    let alliance_ticker = alliance_ticker.filter(|s| !s.is_empty());
    let corp_ticker = corp_ticker.filter(|s| !s.is_empty());
    let mut groups = Vec::with_capacity(3);

    if let Some(t) = alliance_ticker {
        groups.push(t.to_string());
    }
    if let Some(t) = corp_ticker {
        groups.push(t.to_string());
    }
    if let (Some(alliance), Some(corp)) = (alliance_ticker, corp_ticker) {
        groups.push(format!("{alliance}>{corp}"));
    }

    groups
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::{build_display_name, build_ticker_groups};

    #[test]
    fn display_name_uses_known_tickers() {
        assert_eq!(
            build_display_name(Some("ALLY"), Some("CORP"), "Pilot Name"),
            "ALLY-CORP-Pilot Name"
        );
    }

    #[test]
    fn display_name_skips_missing_tickers() {
        assert_eq!(
            build_display_name(None, Some("CORP"), "Pilot Name"),
            "CORP-Pilot Name"
        );
        assert_eq!(
            build_display_name(Some("ALLY"), None, "Pilot Name"),
            "ALLY-Pilot Name"
        );
        assert_eq!(build_display_name(None, None, "Pilot Name"), "Pilot Name");
    }

    #[test]
    fn ticker_groups_include_alliance_corp_and_pair() {
        assert_eq!(
            build_ticker_groups(Some("ALLY"), Some("CORP")),
            vec![
                "ALLY".to_string(),
                "CORP".to_string(),
                "ALLY>CORP".to_string(),
            ]
        );
    }

    #[test]
    fn ticker_groups_skip_missing_tickers() {
        assert_eq!(
            build_ticker_groups(None, Some("CORP")),
            vec!["CORP".to_string()]
        );
        assert_eq!(
            build_ticker_groups(Some("ALLY"), None),
            vec!["ALLY".to_string()]
        );
        assert!(build_ticker_groups(Some(""), Some("")).is_empty());
    }
}
