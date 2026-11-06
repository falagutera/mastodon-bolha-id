# id

A small OpenID Connect provider for one Mastodon instance. Tools such as Penpot, Overleaf, Forgejo or Grafana sign people in with standard OIDC, and the person signs in with their Mastodon account. Only approved, confirmed and active local accounts get through.

It exists because Mastodon is an OAuth 2 server but not an OpenID Connect provider: it issues no `id_token`, has no `/.well-known/openid-configuration`, and its userinfo has no e-mail. This app fills the gap. It runs at `id.bolha.us` for `bolha.us`.

- Discovery, JWKS, authorization code flow with PKCE (S256), token, userinfo and RP-initiated logout
- `id_token` signed with RS256; two keys in the JWKS for rotation
- Account status checked with the instance's admin API at every authorization and refresh: a suspended account loses access
- Consent page in Portuguese and English the first time an account uses a tool; the choice is remembered
- A 12-hour session here, so a second tool doesn't ask to sign in on the instance again
- Optional refresh tokens (`offline_access`), single use and rotated
- Audit log of sign-ins, consents, refusals and sign-outs, without tokens
- Stateless replicas: everything lives in Redis and PostgreSQL

## How it works

```
 Tool (RP)             id.bolha.us                          bolha.us (Mastodon)
    |                       |                                       |
    |-- /authorize -------->| validate client, exact redirect_uri,  |
    |   (client_id,         | scope=openid, PKCE, state, nonce      |
    |    redirect_uri,      |                                       |
    |    state, nonce,      |-- no session here: /oauth/authorize ->|  person signs in
    |    code_challenge)    |   (own OAuth app, scope "profile",    |  on the instance
    |                       |    own state + PKCE, state cookie)    |
    |                       |<-------------- /callback?code --------|
    |                       |-- POST /oauth/token ----------------->|
    |                       |-- GET verify_credentials ------------>|  -> account id
    |                       |-- POST /oauth/revoke ---------------->|  token dropped
    |                       |-- GET /api/v1/admin/accounts/:id ---->|  service token:
    |                       |   approved? confirmed? not suspended? |  e-mail, role,
    |                       |   not disabled? local?                |  status
    |                       |   -> session cookie here (12 h)       |
    |                       |                                       |
    |                       | consent page (first time per tool)    |
    |<-- redirect_uri?code&state&iss                                |
    |                       |                                       |
    |-- POST /token ------->| client auth, code (60 s, single use), |
    |   code, verifier      | PKCE check                            |
    |<-- id_token, access_token (10 min), refresh_token (optional)  |
    |                       |                                       |
    |-- GET /userinfo ----->| Bearer access_token -> claims         |
```

The person's Mastodon token is revoked as soon as the account id is known. The app never holds a token of the person's account.

## Endpoints

| Path | What |
|---|---|
| `/.well-known/openid-configuration` | Discovery |
| `/jwks.json` | Public signing keys |
| `GET /authorize` | Authorization endpoint, `response_type=code` only |
| `GET /callback` | Return from the instance (the Mastodon app's redirect URI) |
| `POST /consent` | The consent form |
| `POST /token` | `authorization_code` and `refresh_token` grants |
| `GET, POST /userinfo` | Claims for a Bearer access token |
| `GET, POST /logout` | `end_session_endpoint` |
| `/healthz` | Redis and PostgreSQL reachable |
| `/release-notes`, `/release-notes.json` | From CHANGELOG.md |
| `/` | A short page about the service, in Portuguese and English |

### Claims

| Claim | Scope | Value |
|---|---|---|
| `sub` | always | The Mastodon account id. Stable: the @ can change, the id can't |
| `preferred_username`, `name`, `picture`, `profile` | `profile` | Username, display name, avatar URL, profile URL |
| `email`, `email_verified` | `email` | The account's e-mail; always confirmed, since unconfirmed accounts are refused |
| `groups`, `role` | `profile` or `groups` | The instance role name, such as `Owner`, `Admin` or `Moderator`; absent for regular accounts |
| `auth_time`, `nonce` | `id_token` | When the person signed in on the instance; the client's nonce |

Supported scopes: `openid` (required), `profile`, `email`, `groups`, `offline_access`. Others are ignored. `prompt=none|login|consent`, `max_age` and `ui_locales` are honored. Request objects are not supported.

## Configuration

All configuration is in environment variables. See `.env.example`.

| Variable | Required | Default | What |
|---|---|---|---|
| `ID_ISSUER` | yes | | `https://id.bolha.us`. https, no path. The `iss` of every token |
| `ID_INSTANCE` | yes | | `https://bolha.us` |
| `ID_MASTODON_CLIENT_ID`, `ID_MASTODON_CLIENT_SECRET` | yes | | The OAuth app on the instance |
| `ID_MASTODON_ADMIN_TOKEN` | yes | | Service account token with `admin:read:accounts` |
| `ID_SIGNING_KEY` or `ID_SIGNING_KEY_FILE` | yes | | RSA private key, PEM (PKCS#1 or PKCS#8), at least 2048 bits |
| `ID_SIGNING_KEY_PREVIOUS` or `ID_SIGNING_KEY_PREVIOUS_FILE` | no | | The key before the last rotation: only published in the JWKS |
| `ID_CLIENTS_FILE` | yes | | Path of the clients JSON file |
| `ID_DB_HOST`, `ID_DB_PASSWORD` | yes | | PostgreSQL |
| `ID_DB_PORT`, `ID_DB_USER`, `ID_DB_NAME`, `ID_DB_SSLMODE` | no | `5432`, `id`, `id`, `prefer` | |
| `ID_REDIS_ADDR` | yes | | `host:port` |
| `ID_REDIS_PASSWORD` | no | | |
| `ID_LISTEN` | no | `:8080` | |
| `ID_LANG` | no | `pt-BR` | Page language when the browser doesn't say (`pt-BR` or `en`) |
| `ID_ALLOW_SILENCED` | no | `true` | Whether silenced (limited) accounts can sign in |
| `ID_SESSION_TTL` | no | `12h` | The session here; within it, tools don't send people to the instance again |
| `ID_REFRESH_TTL` | no | `720h` | Lifetime of a refresh token (each use gives a new one) |

Fixed lifetimes: authorization code 60 s, access token and `id_token` 10 min, pending sign-in 10 min, account status cache 5 min.

## Registering a client

Clients are in a JSON file (a ConfigMap in k8s), loaded at startup. See `clients.example.json`.

```json
{
  "clients": [
    {
      "id": "penpot",
      "name": "Penpot",
      "secret_env": "ID_CLIENT_SECRET_PENPOT",
      "redirect_uris": ["https://penpot.bolha.in/api/auth/oauth/oidc/callback"],
      "post_logout_redirect_uris": ["https://penpot.bolha.in/"]
    }
  ]
}
```

- `id`: the `client_id`. `name`: shown on the consent page.
- `redirect_uris`: compared exactly, including the query. https only (http allowed on `localhost`/`127.0.0.1` for development). No fragments.
- Confidential clients (the default) authenticate at `/token` with `client_secret_basic` or `client_secret_post`. Give the secret one of two ways:
  - `secret_env`: the name of an environment variable that holds it (a k8s Secret). At least 32 characters.
  - `secret_sha256`: the hex SHA-256 of the secret, so the file holds no secret. `printf %s "$SECRET" | sha256sum`.
  
  Generate secrets with `openssl rand -base64 32`. They are compared as SHA-256 hashes, so they must be random: don't use passwords.
- `"public": true` for apps that can't keep a secret (SPAs, desktop). They must use PKCE S256.
- Confidential clients may use PKCE too; when they send a `code_challenge`, the verifier is required.
- `post_logout_redirect_uris`: where `/logout` may send people back. Without it, logout shows a page here.

Restart the app (roll the Deployment) after changing the file.

In the tool, the issuer is `https://id.bolha.us`; most tools only need that, the client id and the secret. Ask for `openid profile email`.

## Setting up the instance side

### OAuth application

Register the app the person signs in through. Its only scope is `profile`, so it can read who the person is and nothing else:

```sh
curl -F client_name=id.bolha.us \
  -F scopes=profile \
  -F redirect_uris=https://id.bolha.us/callback \
  -F website=https://id.bolha.us \
  https://bolha.us/api/v1/apps
```

Put `client_id` and `client_secret` in `ID_MASTODON_CLIENT_ID` and `ID_MASTODON_CLIENT_SECRET`. The `profile` scope with `verify_credentials` needs Mastodon 4.3 or later.

### Service account

The app reads e-mail, role and status with the admin API. Create a dedicated account (for example `idbot`), give it a role whose only permission is **Manage Users** (needed for `admin:read:accounts`), and create a token for it with only the `admin:read:accounts` scope: in Preferences, Development, New application, scope `admin:read:accounts`, then copy "Your access token". Put it in `ID_MASTODON_ADMIN_TOKEN`.

This token can read every account's e-mail and IP data. Keep it in a Secret, and don't reuse it elsewhere.

### Signing key

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing-key.pem
```

To rotate: move the current key to `ID_SIGNING_KEY_PREVIOUS`, put a new one in `ID_SIGNING_KEY`, roll the Deployment. Tokens signed with the old key keep verifying. Remove the previous key after a day (clients cache the JWKS; `id_token`s live 10 minutes).

## Database

PostgreSQL holds consents and the audit log; Redis holds everything short-lived (pending requests, sign-ins in progress, sessions, codes, access and refresh tokens, a 5-minute cache of account status). All Redis keys are SHA-256 hashes of the secret values, with a TTL.

Apply the schema as the database owner. The app user can't change the schema and can only add to the audit log:

```sh
psql -U postgres -c "CREATE ROLE id LOGIN PASSWORD 'change-me'" -c "CREATE DATABASE id"
psql -U postgres -d id -f schema.sql
```

It works behind pgbouncer in transaction mode (simple protocol, 3 connections per replica).

Losing Redis signs everyone out of this app and invalidates outstanding tokens and refresh tokens: tools will send people through the sign-in again. Consents survive.

### Audit log

`audit_log` has one row per event: `login` (a code was issued to a client), `consent`, `deny`, `refused` (with the reason: `suspended`, `disabled`, `unapproved`, `unconfirmed`, `no_email`, `silenced`, `remote`, `gone`), `refresh` and `logout`. It holds the account id, username, client id and time. Never tokens, codes, secrets or IPs.

## Security notes

- Before the client and the exact redirect URI are validated, errors show a page here and never redirect.
- The authorization request, the sign-in on the instance and the consent are each bound: a random `state` with a `__Host-` cookie for the instance round trip, and the session's CSRF token plus the account id for the consent form, which also requires `Sec-Fetch-Site: same-origin`.
- Codes are single use (Redis `GETDEL`), even across replicas, and bound to the client, redirect URI, PKCE challenge and nonce. A failed exchange burns the code.
- Authorization responses carry `iss` (RFC 9207).
- The account is checked at every authorization (cache of at most 5 minutes), at userinfo, and directly with the instance at every refresh.
- Strict CSP (`default-src 'none'`, no inline script or style). The consent page allows the client's redirect origin in `form-action`, because browsers check it across the redirect.
- Request bodies are capped at 64 KiB. Rate limiting is expected at the edge.
- `/logout` accepts GET without confirmation, as OpenID Connect RP-initiated logout does: another site can sign someone out of this app (not out of the tools).
- Logging out here doesn't end sessions in the tools, and outstanding refresh tokens stay valid until used (then the account is checked) or expired.

## Versions

Versions look like `X.Y.Z-BUILD`. `X.Y.Z` is in the `VERSION` file and follows SemVer, and `BUILD` is the GitLab pipeline number. A local build shows `X.Y.Z-dev`. The page footer shows the version.

What changed in each version is in [CHANGELOG.md](CHANGELOG.md), served as `/release-notes` and `/release-notes.json`. Add an entry when you bump `VERSION`: a test fails without it.

| Image tag | Moves? |
|---|---|
| `registry.gutocarvalho.net/images/id:X.Y.Z-BUILD` | Never. Pin this one in production. |
| `X.Y.Z` | On each build of that version. |
| `latest` | On each build. |

## Deploy notes

- Run 2 or more replicas: there is no in-memory state.
- Mount the clients file (ConfigMap) and the signing key (Secret, via `ID_SIGNING_KEY_FILE`); put the Mastodon secrets, the admin token and client secrets in Secrets.
- The container listens on `:8080`, runs as nonroot on distroless, and has `/id -healthcheck` for Docker. In k8s, probe `GET /healthz`.
- Serve it over HTTPS at the issuer URL. The cookies are `Secure` with the `__Host-` prefix.
- At the edge: rate limit `/authorize`, `/callback`, `/token` and `/userinfo`. A JavaScript challenge (Anubis) must not cover `/token`, `/userinfo`, `/jwks.json` or `/.well-known/`: tools call them server-to-server.

## Development

```sh
go vet ./... && gofmt -l .
go test ./...    # unit tests; the flow tests skip without a database
```

The flow tests run the whole sign-in against a fake Mastodon and need PostgreSQL and Redis:

```sh
docker run -d --rm --name id-pg -p 55432:5432 -e POSTGRES_PASSWORD=admin postgres:17-alpine
docker run -d --rm --name id-redis -p 56379:6379 redis:7.4-alpine
docker exec id-pg psql -U postgres -c "CREATE ROLE id LOGIN PASSWORD 'id'" -c "CREATE DATABASE id"
docker exec -i id-pg psql -U postgres -d id < schema.sql
ID_TEST_DB_HOST=127.0.0.1 ID_TEST_DB_PORT=55432 ID_TEST_REDIS=127.0.0.1:56379 go test -p 1 ./...
docker rm -f id-pg id-redis
```

## License

AGPL-3.0, see [LICENSE](LICENSE). Fonts: see [NOTICE](NOTICE).
