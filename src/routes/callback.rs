use std::fmt::Write as _;
use std::time::Instant;

use axum::{
    extract::{Query, State},
    response::Html,
};
use serde::Deserialize;
use url::Url;

use crate::config::{Config, MumbleServer};
use crate::error::AppError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

pub async fn handle(
    State(s): State<AppState>,
    Query(p): Query<Params>,
) -> Result<Html<String>, AppError> {
    if let Some(err) = p.error {
        return Err(AppError::BadRequest(format!(
            "EVE SSO error: {err} ({})",
            p.error_description.unwrap_or_default()
        )));
    }

    let code = p
        .code
        .ok_or_else(|| AppError::BadRequest("missing code".into()))?;
    let state = p
        .state
        .ok_or_else(|| AppError::BadRequest("missing state".into()))?;

    let entry = s
        .pkce
        .remove(&state)
        .map(|(_, v)| v)
        .ok_or_else(|| AppError::BadRequest("unknown or expired state".into()))?;
    if entry.expires_at < Instant::now() {
        return Err(AppError::BadRequest("state expired".into()));
    }

    let token = s
        .sso
        .exchange_code(&code, &entry.verifier, &s.cfg.redirect_uri())
        .await?;

    // Sanity-verify the JWT now: we want to fail loudly if the client_id is
    // misconfigured (audience mismatch) rather than silently handing the user
    // a credential that will be rejected by /auth later.
    let claims = s.sso.verify_access_token(&token.access_token).await?;
    let char_id = claims.character_id()?;

    Ok(Html(render_picker(
        &claims.name,
        char_id,
        &token.access_token,
        &s.cfg,
    )?))
}

fn render_picker(
    char_name: &str,
    char_id: u64,
    jwt: &str,
    cfg: &Config,
) -> Result<String, AppError> {
    let username = format!("{char_id}@{}", cfg.public_domain);

    let mut links = String::new();
    for srv in &cfg.mumble_servers {
        let server_name = srv.name.as_deref().unwrap_or(&srv.host);
        let title = format!("{} ({})", cfg.cluster_name, server_name);
        let mumble_url =
            build_mumble_url(srv, &username, jwt, &title, cfg.mumble_url.as_deref())?;
        let host_line = if srv.port == 64738 {
            srv.host.clone()
        } else {
            format!("{}:{}", srv.host, srv.port)
        };
        let _ = write!(
            links,
            r#"<a class="server" href="{href}"><div class="title">{title}</div><div class="host">{host}</div></a>"#,
            href = escape_html(&mumble_url),
            title = escape_html(&title),
            host = escape_html(&host_line),
        );
    }

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVE → Mumble</title>
<style>
  :root {{ color-scheme: light dark; --bg: #fff; --fg: #222; --muted: #666; --host: #888; --border: #ddd; --border-hover: #999; --hover-bg: #f6f6f6; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #1a1a1a; --fg: #e6e6e6; --muted: #aaa; --host: #888; --border: #333; --border-hover: #666; --hover-bg: #262626; }}
  }}
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; max-width: 540px; margin: 3em auto; padding: 0 1em; background: var(--bg); color: var(--fg); }}
  h1 {{ font-size: 1.4em; margin-bottom: 0.25em; }}
  p {{ color: var(--muted); margin-top: 0; }}
  .server {{ display: block; padding: 0.9em 1em; margin: 0.5em 0; border: 1px solid var(--border); border-radius: 8px; text-decoration: none; color: inherit; }}
  .server:hover {{ background: var(--hover-bg); border-color: var(--border-hover); }}
  .title {{ font-weight: 600; }}
  .host {{ color: var(--host); font-size: 0.9em; margin-top: 0.2em; }}
</style>
</head>
<body>
<h1>Welcome, {name}</h1>
<p>Pick a Mumble server:</p>
{links}
</body>
</html>
"#,
        name = escape_html(char_name),
        links = links,
    ))
}

fn build_mumble_url(
    srv: &MumbleServer,
    username: &str,
    jwt: &str,
    title: &str,
    url_param: Option<&str>,
) -> Result<String, AppError> {
    let mut url = Url::parse(&format!("mumble://{}:{}/", srv.host, srv.port))
        .map_err(|e| AppError::Internal(format!("bad mumble base url: {e}")))?;
    url.set_username(username)
        .map_err(|_| AppError::Internal("set username failed".into()))?;
    url.set_password(Some(jwt))
        .map_err(|_| AppError::Internal("set password failed".into()))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("title", title);
        if let Some(u) = url_param {
            q.append_pair("url", u);
        }
    }
    Ok(url.into())
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
