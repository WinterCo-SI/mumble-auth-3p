use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub mod auth;
pub mod callback;
pub mod health;
pub mod login;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(login::start))
        .route("/callback", get(callback::handle))
        .route("/auth", post(auth::handle))
        .route("/healthz", get(health::ok))
        .with_state(state)
}
