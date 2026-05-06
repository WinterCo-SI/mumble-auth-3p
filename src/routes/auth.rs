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

    Ok(Json(AuthResponse {
        user_id: char_id,
        display_name: claims.name,
        groups: decision.groups,
    }))
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
