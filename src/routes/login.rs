use std::time::{Duration, Instant};

use axum::{extract::State, response::Redirect};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::AppError;
use crate::state::{AppState, PkceEntry};

const PKCE_TTL: Duration = Duration::from_secs(600);

pub async fn start(State(s): State<AppState>) -> Result<Redirect, AppError> {
    let state = random_b64(32);
    let verifier = random_b64(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    s.pkce.insert(
        state.clone(),
        PkceEntry {
            verifier,
            expires_at: Instant::now() + PKCE_TTL,
        },
    );
    prune(&s);

    let auth_endpoint = s.sso.discovery().await?.authorization_endpoint;
    let mut url = Url::parse(&auth_endpoint)
        .map_err(|e| AppError::Internal(format!("bad authorization_endpoint: {e}")))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &s.cfg.eve_client_id)
        .append_pair("redirect_uri", &s.cfg.redirect_uri())
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Redirect::to(url.as_str()))
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn prune(s: &AppState) {
    let now = Instant::now();
    s.pkce.retain(|_, v| v.expires_at > now);
}
