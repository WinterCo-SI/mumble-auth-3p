# eve-mumble-bridge

A small Rust service that lets EVE Online players authenticate to a Mumble
server using their EVE SSO identity. It plays two roles:

1. A web app users visit in a browser. It walks them through EVE SSO and hands
   back a `mumble://` link (and copy-pasteable credentials) for each configured
   server.
2. An HTTP backend the Mumble server's auth plugin calls on every connection
   to verify the credentials and resolve the user's display name and groups.

No database. No user accounts. Identity is the EVE JWT; whitelist and group
membership are read from a TOML file at startup.

## How it works

```
   browser              eve-mumble-bridge          EVE SSO / ESI       Mumble
   -------              -----------------          -------------       ------
GET  /              ─►  PKCE + redirect      ─►   login.eveonline.com
                   ◄─   redirect to SSO

GET  /callback?code ─►  exchange code        ─►   token endpoint
                        verify JWT (JWKS)
                        render picker page
                   ◄─   HTML with mumble:// links

                                                                       click
                                                                  ─►   user@host
                                                                       password=JWT

POST /auth          ◄─  Bearer auth_token, JSON {username, password}    ◄─  plugin
                        verify JWT signature + iss/aud/exp/iat
                        check whitelist via ESI affiliation
                        resolve corp/alliance ticker (cached)
                   ─►   {user_id, display_name, groups}                 ─►  plugin
```

The Mumble password is the user's EVE access token. The bridge re-validates it
on every `/auth` call, so a Mumble reconnect after the token expires fails
naturally (the user just logs in again).

## Quick start

```sh
cargo build --release
cp config.example.toml config.toml
# edit config.toml: EVE app credentials, Mumble auth_token, servers, whitelist
./target/release/eve-mumble-bridge ./config.toml
```

The default config path is `./config.toml`; pass an alternate path as the first
CLI argument.

You'll need an EVE developer application at
<https://developers.eveonline.com/>:

- Connection type: **Authentication only** (no scopes required)
- Callback URL: `<public_url>/callback`

## Endpoints

| Method | Path        | Purpose                                          |
| ------ | ----------- | ------------------------------------------------ |
| GET    | `/`         | Begin EVE SSO login (PKCE, redirects to EVE).    |
| GET    | `/callback` | OAuth callback. Renders the server picker page.  |
| POST   | `/auth`     | Mumble plugin entry point. Bearer-auth + JSON.   |
| GET    | `/healthz`  | Liveness probe.                                  |

### `POST /auth`

Headers: `Authorization: Bearer <mumble.auth_token>`

Request:

```json
{ "username": "<character_id>@<public_domain>", "password": "<eve_jwt>" }
```

Response:

```json
{
  "user_id": 91234567,
  "display_name": "BRAVE-BRN-Pilot Name",
  "groups": ["char_91234567", "corp_98123456", "alliance_99003581", "officers"]
}
```

`display_name` is `{alliance_ticker}-{corp_ticker}-{character_name}`, with
either ticker dropped when unknown. Tickers come from a persistent on-disk
cache (`cache.path`); entries are immutable once written.

## Configuration

See [`config.example.toml`](config.example.toml) for the full schema with
inline comments. The interesting bits:

- **`public_url`** — used to build the OAuth `redirect_uri` and the Mumble
  username suffix. Must match what the EVE app is registered with.
- **`cluster_name`** — shown in the picker page heading and as the
  `?title=` query param on each `mumble://` link.
- **`mumble.auth_token`** — shared secret between this service and the Mumble
  auth plugin. Generate something long and random.
- **`[whitelist]`** — anyone matching any `alliance_ids` / `corporation_ids` /
  `character_ids` entry is admitted. Empty whitelist means no one gets in.
- **`[groups.<name>]`** — same shape as `[whitelist]`. A user gets the named
  group if they match its rules. Auto-generated groups (`char_<id>`,
  `corp_<id>`, `alliance_<id>`) are added on top.
- **`[jwt]`** — `validate_exp` enforces the token's ~20-minute expiry.
  `max_age_seconds` is an independent ceiling on token age (uses the `iat`
  claim). Use one, the other, or both.

## Development

```sh
cargo test
cargo run -- ./config.toml
```

Logging is controlled by `log_filter` in the config (a
`tracing-subscriber` `EnvFilter` string).
