use axum::http::StatusCode;

pub async fn ok() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}
