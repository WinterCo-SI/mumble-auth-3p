use std::fmt::Write as _;
use std::time::Instant;

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

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
) -> Result<Response, AppError> {
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

    let Some(entry) = s.pkce.remove(&state).map(|(_, v)| v) else {
        return Ok(Redirect::to("/").into_response());
    };
    if entry.expires_at < Instant::now() {
        return Ok(Redirect::to("/").into_response());
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
    )?)
    .into_response())
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
            build_mumble_url(srv, &username, jwt, &title, cfg.mumble_url.as_deref());
        let host_line = if srv.port == 64738 {
            srv.host.clone()
        } else {
            format!("{}:{}", srv.host, srv.port)
        };
        let _ = write!(
            links,
            r#"<a class="server" href="{href}"><div class="title">{title}</div><div class="host">{host}</div></a>"#,
            href = escape_html(&mumble_url),
            title = escape_html(&server_name),
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
  :root {{ color-scheme: light dark; --bg: #fff; --fg: #222; --muted: #666; --host: #888; --border: #ddd; --border-hover: #999; --hover-bg: #f6f6f6; --input-bg: #fafafa; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #1a1a1a; --fg: #e6e6e6; --muted: #aaa; --host: #888; --border: #333; --border-hover: #666; --hover-bg: #262626; --input-bg: #0f0f0f; }}
  }}
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; max-width: 540px; margin: 3em auto; padding: 0 1em; background: var(--bg); color: var(--fg); }}
  h1 {{ font-size: 1.4em; margin-bottom: 0.25em; }}
  h2 {{ font-size: 1em; color: var(--muted); margin-top: 2em; margin-bottom: 0.5em; font-weight: 600; }}
  p {{ color: var(--muted); margin-top: 0; }}
  .server {{ display: block; padding: 0.9em 1em; margin: 0.5em 0; border: 1px solid var(--border); border-radius: 8px; text-decoration: none; color: inherit; }}
  .server:hover {{ background: var(--hover-bg); border-color: var(--border-hover); }}
  .title {{ font-weight: 600; }}
  .host {{ color: var(--host); font-size: 0.9em; margin-top: 0.2em; }}
  .cred-row {{ display: flex; align-items: center; gap: 0.5em; margin: 0.4em 0; }}
  .cred-label {{ flex: 0 0 5.5em; color: var(--muted); font-size: 0.9em; }}
  .cred-input {{ flex: 1; min-width: 0; padding: 0.5em 0.6em; border: 1px solid var(--border); border-radius: 6px; background: var(--input-bg); color: var(--fg); font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; font-size: 0.85em; }}
  .cred-btn {{ padding: 0.5em 0.8em; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--fg); cursor: pointer; font-size: 0.85em; }}
  .cred-btn:hover {{ background: var(--hover-bg); border-color: var(--border-hover); }}
</style>
</head>
<body>
<h1>Welcome, {name}</h1>
<p>Click on a Mumble server to connect, or drag the link into the Favorite Servers list:</p>
{links}
<h2>Or connect manually</h2>
<div class="cred-row">
  <span class="cred-label">Username</span>
  <input class="cred-input" type="text" readonly value="{username}" id="cred-username">
  <button class="cred-btn" type="button" data-target="cred-username">Copy</button>
</div>
<div class="cred-row">
  <span class="cred-label">Password</span>
  <input class="cred-input" type="password" readonly value="{password}" id="cred-password">
  <button class="cred-btn" type="button" data-target="cred-password" data-toggle="1">Show</button>
  <button class="cred-btn" type="button" data-target="cred-password">Copy</button>
</div>
<script>
document.querySelectorAll('.cred-btn').forEach(btn => {{
  btn.addEventListener('click', async () => {{
    const el = document.getElementById(btn.dataset.target);
    if (btn.dataset.toggle) {{
      const hidden = el.type === 'password';
      el.type = hidden ? 'text' : 'password';
      btn.textContent = hidden ? 'Hide' : 'Show';
      return;
    }}
    try {{
      await navigator.clipboard.writeText(el.value);
    }} catch (_) {{
      const prev = el.type;
      el.type = 'text';
      el.focus();
      el.select();
      try {{ document.execCommand('copy'); }} catch (_) {{}}
      el.type = prev;
    }}
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {{ btn.textContent = orig; }}, 1500);
  }});
}});
</script>
</body>
</html>
"#,
        name = escape_html(char_name),
        links = links,
        username = escape_html(&username),
        password = escape_html(jwt),
    ))
}

fn build_mumble_url(
    srv: &MumbleServer,
    username: &str,
    jwt: &str,
    title: &str,
    url_param: Option<&str>,
) -> String {
    let mut url = format!(
        "mumble://{username}:{jwt}@{host}:{port}/?title={title}",
        host = srv.host,
        port = srv.port,
    );
    if let Some(u) = url_param {
        url.push_str("&url=");
        url.push_str(u);
    }
    url
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
