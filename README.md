# id

A small OpenID Connect provider for one Mastodon instance. Tools such as Penpot, Overleaf, Forgejo or Grafana sign people in with standard OIDC, and the person signs in with their Mastodon account. Only approved, confirmed and active local accounts get through.

It exists because Mastodon is an OAuth 2 server but not an OpenID Connect provider: it issues no `id_token`, has no `/.well-known/openid-configuration`, and its userinfo has no e-mail. This app fills the gap. It runs at `id.bolha.us` for `bolha.us`.

- Discovery, JWKS, authorization code flow with PKCE (S256), token, userinfo and RP-initiated logout
- `id_token` signed with RS256; two keys in the JWKS for rotation
- Account status checked with the instance's admin API at every authorization and refresh: a suspended account loses access
- Consent page in Portuguese and English the first time an account uses a tool; the choice is remembered
- A short session here (2 hours by default), so a second tool doesn't ask to sign in on the instance again
- Optional refresh tokens (`offline_access`), single use and rotated, with reuse detection: a replayed refresh token or code revokes every token that came from it
- Audit log of sign-ins, consents, refusals and sign-outs, without tokens
- Stateless replicas: everything lives in Redis and PostgreSQL

## Testing and security

This app decides who gets into other tools, so it is tested and reviewed as a security component. What is done today (2026-11-06):

**Every pipeline.** GitLab CI ([`.gitlab-ci.yml`](.gitlab-ci.yml), plus the shared security stage from `open/gcn/ci-templates`, file `security.yml`) runs on every push. The test job runs on every pipeline; the security stage runs on every merge request and every push to `main`; the image is built and published only from `main`.

- Blocking (the pipeline fails and no image is published):
  - `go vet`, a `gofmt` check, and the full test suite against real PostgreSQL 17 and Redis 7.4 services;
  - `govulncheck`: known vulnerabilities in Go code paths this app actually reaches;
  - `gitleaks`: secrets committed to the repository;
  - `trivy`: critical vulnerabilities that have a fix, secrets and misconfigurations in the repository.
- Informative (reported, not blocking): `semgrep`, `gosec`, `hadolint` (Dockerfile), `yamllint`, and `poutine` (security of the CI pipeline itself). At 0.1.0 they report nothing at the thresholds the pipeline uses; the few `gosec`/`semgrep` false positives are annotated in the code with the reason.

**The test suite.** 51 tests, all run with the race detector (`go test -race`). Most run the real HTTP handlers end to end against a fake Mastodon server, PostgreSQL and Redis:

- the full OpenID Connect flow: authorize, sign-in on the instance, consent, token, `id_token` signature checked against the published JWKS, userinfo, and that the person's Mastodon token is revoked;
- redirect URIs: exact match only, and errors before validation never redirect;
- PKCE (S256 only, exact length, wrong or missing verifier), client authentication (wrong secret, another client's code, both methods at once), single-use codes;
- consent and sign-out forms: CSRF token, same-origin check, form reused from another browser;
- account status: suspended, disabled, unapproved, unconfirmed, remote, deleted and silenced accounts, at sign-in, refresh and userinfo;
- token families: replayed codes and refresh tokens revoke their family, sign-out revokes the account's tokens, a hint-only sign-out revokes only its own family, rotation that fails halfway keeps the old token;
- rate limits and failures of the instance or of Redis (the refresh token survives, the limiter doesn't fail open, concurrent lookups share one admin call);
- signing keys: rotation, forged payloads, `alg: none`, short keys; configuration and clients-file validation; translations; release notes.

**Reviews before the first release.** An independent security code review against OpenID Connect Core, the OAuth 2.0 Security Best Current Practice (RFC 9700) and OWASP ASVS; two automated white-box penetration test runs with [Strix](https://github.com/usestrix/strix); and an automated review of each security-relevant commit. Every finding was fixed with a regression test (most are in `security_test.go`). The fixes are listed in the 0.1.0 entry of the [CHANGELOG](CHANGELOG.md) and in the commit history. These were done by the project, not by an outside auditor, and they don't certify anything: they are what we checked.

**Reporting a vulnerability.** Write to contato@gutocarvalho.net. Please don't open a public issue for it.

## Architecture

**Why it exists.** The bolha community runs many tools (an editor, design, notes, forges, video…), and each one used to have its own sign-up, its own password and its own queue of accounts to approve. `id` centralizes sign-in on the person's **bolha.us** account: a tool connected to it needs no sign-up of its own, and the approval that already happens on bolha.us is the only one.

**In plain words.** Mastodon knows how to authenticate its accounts, but it doesn't speak the standard sign-in protocol most tools understand (OpenID Connect). `id` is a bridge between the two:

1. the tool sends the person to `id.bolha.us`;
2. `id` sends the person to `bolha.us`, where they sign in as usual;
3. `id` checks that the account is approved and active, asks the person's consent the first time, and sends them back to the tool, signed in.

**For the people using it:** one password (the bolha.us one) for every connected tool; no new sign-up or approval wait; a consent page that shows what each tool receives (name, @handle and e-mail); and when an account is suspended on bolha.us, its access to the tools ends too.

**Components.**

```
                 browser
                    |
   +----------------+-----------------+
   |                                  |
 Tool (relying party)          id.bolha.us  (this app, 2 stateless replicas)
 Penpot, Overleaf, ...          |      |        |
   |  /token, /userinfo,        |      |        +--> Redis       sessions, codes, tokens,
   |  /jwks.json (server to     |      |             (hashed, with TTL), status cache
   |  server)                   |      +----------> PostgreSQL  consents, audit log
   +--------------------------->|
                                +--> bolha.us (Mastodon)
                                      - OAuth: the person signs in, id learns the account id
                                      - admin API (read-only service token): e-mail,
                                        role, approved / confirmed / suspended / disabled
```

- `id` keeps no password and no Mastodon token of the person: the sign-in token is revoked as soon as the account id is known.
- Tools only receive standard OpenID Connect: an `id_token` signed by `id` (keys published at `/jwks.json`), and claims at `/userinfo`. They key accounts on `sub`, the stable bolha.us account id.
- Admin rights in a tool come from the `groups` claim, mapped from bolha.us roles by `ID_ROLE_GROUPS` (only listed roles produce a group).
- At bolha, `id` runs in Kubernetes behind the same edge as the other services (nginx, BunkerWeb, Anubis on the browser pages only).

## How it works (protocol detail)

The same flow, step by step, as a tool developer sees it:

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
    |                       |   -> session cookie here (2 h)        |
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
| `sub` | always | The Mastodon account id. Stable: the @ can change, the id can't. Tools must key accounts on `sub`, never on the e-mail or the username |
| `preferred_username`, `name`, `picture`, `profile` | `profile` | Username, display name, avatar URL, profile URL |
| `email`, `email_verified` | `email` | The account's e-mail; always confirmed, since unconfirmed accounts are refused |
| `groups`, `role` | `profile` or `groups` | A group name from `ID_ROLE_GROUPS`, keyed by the Mastodon role id (for example `admin`, `moderator`). Roles not in the mapping produce no claim; raw role names are never sent |
| `auth_time`, `nonce` | `id_token` | When the round trip through the instance happened (see the security notes); the client's nonce |
| `sid` | `id_token` | The token family: the same for every `id_token` of one sign-in at one client, refreshes included. Sent back as `id_token_hint` at logout |

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
| `ID_DB_PORT`, `ID_DB_USER`, `ID_DB_NAME`, `ID_DB_SSLMODE` | no | `5432`, `id`, `id`, `require` | Set `disable` only on a trusted local network |
| `ID_REDIS_ADDR`, `ID_REDIS_PASSWORD` | yes | | `host:port` and its password. The app refuses to start without a password |
| `ID_LISTEN` | no | `:8080` | |
| `ID_LANG` | no | `pt-BR` | Page language when the browser doesn't say (`pt-BR` or `en`) |
| `ID_ALLOW_SILENCED` | no | `true` | Whether silenced (limited) accounts can sign in |
| `ID_SESSION_TTL` | no | `2h` | The session here; within it, tools don't send people to the instance again. Kept short for shared devices: signing out of a tool doesn't end it |
| `ID_ROLE_GROUPS` | no | none | JSON object from Mastodon role id to group name, such as `{"3":"admin","2":"moderator"}`. Role ids are in the instance's admin UI (Roles) or `GET /api/v1/admin/accounts/:id` |
| `ID_REFRESH_TTL` | no | `720h` | Lifetime of a refresh token (each use gives a new one) |
| `ID_LINK_PEERTUBE_DSN` or `ID_LINK_PEERTUBE_DSN_FILE` | no | | PostgreSQL DSN of PeerTube's database, for clients with `"account_link": "peertube"`. Without it those clients sign in without the linking offer. See [docs/account-linking.md](docs/account-linking.md) |
| `ID_LINK_PEERTUBE_PLUGIN` | no | `peertube-plugin-auth-openid-connect` | npm name of the PeerTube auth plugin the linked accounts move to |

Fixed values: authorization code 60 s, access token and `id_token` 10 min, pending sign-in 10 min, account status cache 5 min (1 min on refresh, 1 min for "account doesn't exist"), 30 refreshes per minute per account and client, and 600 per client.

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
- `redirect_uris`: compared exactly, including the query. https only; `http://localhost`/`127.0.0.1` only for a client with `"dev": true`. No fragments.
- Confidential clients (the default) authenticate at `/token` with `client_secret_basic` or `client_secret_post`. Give the secret one of two ways:
  - `secret_env`: the name of an environment variable that holds it (a k8s Secret). At least 32 characters.
  - `secret_sha256`: the hex SHA-256 of the secret, so the file holds no secret. `printf %s "$SECRET" | sha256sum`.
  
  Generate secrets with `openssl rand -base64 32`. They are compared as SHA-256 hashes, so they must be random: don't use passwords.
- `"public": true` for apps that can't keep a secret (SPAs, desktop). They must use PKCE S256.
- Confidential clients must send a PKCE `code_challenge` (S256), a `nonce`, or both; a request with neither is refused. When they send a `code_challenge`, the verifier is required.
- `"lowercase_username": true` sends `preferred_username` in lower case, for apps that only accept lower-case usernames (PeerTube). Mastodon usernames are unique ignoring case, so this cannot make two people share a name.
- `"allow_no_pkce_or_nonce": true` (confidential clients only; refused on a public client at startup; off by default) lets a client sign in with neither, for RP libraries that only send `state`, such as passport-openidconnect 0.1.x (Overleaf). Whatever PKCE or nonce such a client does send is still checked. The app logs a warning at startup for each client that has it. Remove it as soon as the tool supports PKCE; see the security notes.
- `"account_link": "peertube"`: the consent page offers to link the person's existing password account in that PeerTube (same e-mail as the confirmed one on the instance), so they can sign in to it from here. Needs `ID_LINK_PEERTUBE_DSN`; see [docs/account-linking.md](docs/account-linking.md).
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

The app reads e-mail, role and status with the admin API. Create a dedicated account (for example `identifica`), give it a role whose only permission is **Manage Users** (needed for `admin:read:accounts`), and create a token for it with only the `admin:read:accounts` scope: in Preferences, Development, New application, scope `admin:read:accounts`, then copy "Your access token". Put it in `ID_MASTODON_ADMIN_TOKEN`.

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

`audit_log` has one row per event (fields are stripped of control characters and cut at 200 characters; `/logout` records the client id only when it is a registered client): `login` (a code was issued to a client), `consent`, `deny`, `refused` (with the reason: `suspended`, `disabled`, `unapproved`, `unconfirmed`, `no_email`, `silenced`, `remote`, `gone`), `link` (an existing account in the tool was linked, with its username), `refresh` and `logout`. It holds the account id, username, client id and time. Never tokens, codes, secrets or IPs.

## Security notes

- Before the client and the exact redirect URI are validated, errors show a page here and never redirect.
- The authorization request, the sign-in on the instance and the consent are each bound: a random `state` with a `__Host-` cookie for the instance round trip, and the session's CSRF token plus the account id for the consent form, which also requires `Sec-Fetch-Site: same-origin`.
- Clients with `allow_no_pkce_or_nonce` lose the binding PKCE or a nonce gives between the code and the browser session that started the flow, so they are exposed to authorization code injection (RFC 9700 §4.5): someone who obtains a victim's code could try to redeem it in their own session at that tool. What still limits it: the code is redeemed only with the client's secret, only for the exact registered redirect URI, lives 60 seconds, works once and is bound to that client; and the tool checks `state`. It exists only for legacy RP libraries and should be removed once the tool supports PKCE.
- Codes are single use (Redis `GETDEL`), even across replicas, and bound to the client, redirect URI, PKCE challenge (exactly 43 characters, S256) and nonce. A failed exchange burns the code.
- Every code starts a token family; its access and refresh tokens carry it. A code redeemed twice, or a rotated refresh token presented again, revokes the whole family (RFC 6749 4.1.2, RFC 9700 4.14.2): its live tokens are deleted and userinfo and refresh refuse the family from then on. Two refreshes of the same token racing each other: one wins, the other gets `invalid_grant` without revoking anything.
- Refresh looks the token up without consuming it, checks the client, the family, a rate limit (30/min per account and client, so one looping tool can't block the person's other tools; 600/min per client; `429 slow_down` with `Retry-After`) and the account. Then it stores the successor tokens first and only after that consumes the old one (atomically marking it used): a failure while storing leaves the old token valid and unmarked, so the client's retry isn't taken for reuse. If the consume loses a race, the successors are deleted. The limiter is a Lua script (INCR, expiry set on the first hit and repaired if missing), works on any Redis version, and refuses the request (503) when Redis fails instead of letting it through. When the instance fails (5xx, timeout, a 429 of its own, a 404 that isn't Mastodon's JSON), the answer is `503 temporarily_unavailable` with `Retry-After` and the refresh token still works. A 429 from the instance is logged as such.
- Account status lookups go through one shared cache: concurrent lookups for an account, on any replica, make one admin API call (a Redis lock). An account the instance says doesn't exist (Mastodon's JSON 404) is cached for a minute, so tokens of a deleted account don't hit the admin API on every request.
- Signing out here (`/logout` with a session) revokes every token family of the account, so refresh tokens and access tokens stop working in every tool. RP-initiated logout with a valid `id_token_hint` (signature, issuer, `aud` a registered client, issued within the refresh token lifetime) and no session here revokes only the hint's own token family (its `sid`), audited as `logout` with detail `id_token_hint`. An `id_token` can leak from a tool's cookies or browser storage and an expired one is still accepted as a hint, so on its own it must not be able to sign the person out of every other tool.
- Authorization responses carry `iss` (RFC 9207).
- The account is checked at every authorization (cache of at most 5 minutes), at userinfo, and directly with the instance at every refresh.
- Strict CSP (`default-src 'none'`, no inline script or style). The consent page allows the client's redirect origin in `form-action`, because browsers check it across the redirect.
- Request bodies are capped at 64 KiB. Rate limiting is expected at the edge.
- `prompt=login`, `select_account` and `max_age` send `force_login=true` to the instance, which ends the person's session on bolha.us itself (they sign in again there). This is Mastodon's behaviour and is kept on purpose.
- `auth_time` is when the round trip through the instance happened. Without `force_login`, Mastodon may have reused its own session, so the password may have been typed earlier. Tools that need a recent sign-in should send `max_age`: that always forces a sign-in on the instance.
- Shared devices: the session here lasts 2 hours by default and signing out of a tool doesn't end it. Sign out at `/` (or the tool's logout, if it calls `/logout`).
- `/authorize` stores a pending request in Redis before anyone signs in (10 minutes, `state` up to 512 and `nonce` up to 255 characters). Rate-limit `/authorize` at the edge, and run Redis with `maxmemory` plus `maxmemory-policy noeviction` (or `volatile-ttl`) and a memory alert, so a flood fails loudly instead of evicting sessions and token families.
- Redis holds sessions and tokens (hashed), so it requires a password, and a NetworkPolicy should allow only the id pods to reach it.
- `/logout` only ends the session (and revokes the account's tokens) when the request proves it: an `id_token_hint` issued to this session, or the person confirming on a page here (same-origin POST with the session's CSRF token). A plain link from another site only shows the confirmation page, so it can't sign anyone out.
- Logging out here doesn't end the tools' own sessions; it does revoke the account's tokens issued here.

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
- Mount the clients file (ConfigMap) and the signing key (Secret, via `ID_SIGNING_KEY_FILE`); put the Mastodon secrets, the admin token, the Redis password and client secrets in Secrets.
- Redis: password on, `maxmemory` with `noeviction` (or `volatile-ttl`) and a memory alert, and a NetworkPolicy so only the id pods reach it.
- PostgreSQL over TLS (`ID_DB_SSLMODE=require`, the default).
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
docker exec id-pg psql -U postgres -c "CREATE ROLE id LOGIN PASSWORD 'id'" -c "CREATE DATABASE id_test"
docker exec -i id-pg psql -U postgres -d id_test < schema.sql
ID_TEST_DB_HOST=127.0.0.1 ID_TEST_DB_PORT=55432 ID_TEST_REDIS=127.0.0.1:56379 PGPASSWORD=admin go test -p 1 ./...
docker rm -f id-pg id-redis
```

The tests delete data: they only accept a database whose name ends in `_test`, and flush Redis database 15, never 0.

[AGENTS.md](AGENTS.md) is the guide for changing the code, for people and for coding agents (Claude Code, Codex, Cursor and others read it): the exact test commands, a map of the files and their tests, and the rules a change must keep (exact redirect URIs, single-use bound codes, token families, which accounts may sign in, CSRF, CSP, both languages), each with the test that guards it. `CLAUDE.md` only points to it.

## License

AGPL-3.0, see [LICENSE](LICENSE). Fonts: see [NOTICE](NOTICE).

## Bot account

The app's account on bolha.us, @identifica, is marked as a bot and uses [`docs/bot-avatar.png`](docs/bot-avatar.png) as its avatar, in the style of the other bolha.us bots.
