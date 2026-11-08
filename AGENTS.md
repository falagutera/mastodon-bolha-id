# AGENTS.md

Notes for coding agents (and people) changing id. The README says what the app does, how to
configure and deploy it, and its security notes; this file says how to change it without breaking
them. This app decides who gets into other tools: treat every change as a security change.

## What it is

One Go binary (`package main`, no framework), an OpenID Connect provider in front of one Mastodon
instance. People sign in on the instance; id checks the account with the admin API and issues
standard OIDC tokens to the registered clients. Short-lived state (pending requests, sessions,
codes, tokens, account cache, token families, rate limits) is in Redis; consents and the audit log
are in PostgreSQL (`schema.sql`). Optional account linking writes to a PeerTube database (`link.go`).

## Commands

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./...         # without ID_TEST_DB_HOST / ID_TEST_REDIS the flow tests skip themselves
```

With PostgreSQL and Redis (what CI runs). The tests **delete the consents and flush the Redis
database** they reach, and drop/create a `pt_test` schema: pick free ports, chain with `&&`, and
never point them at a shared server. They refuse a database name that does not end in `_test`
(`testDBName`) and Redis index 0, the one the app uses (`testRedisDB`). `-p 1` is required.

```sh
P=55611 R=55612   # any free ports
docker run -d --name id-pg-$P -p $P:5432 -e POSTGRES_PASSWORD=pg postgres:17-alpine &&
  docker run -d --name id-redis-$R -p $R:6379 redis:7.4-alpine &&
  until docker exec id-pg-$P pg_isready -U postgres -q; do sleep 1; done &&
  docker exec id-pg-$P psql -q -U postgres -c "CREATE ROLE id LOGIN PASSWORD 'id'" -c "CREATE DATABASE id_test" &&
  docker exec -i id-pg-$P psql -q -U postgres -d id_test -v ON_ERROR_STOP=1 -f - < schema.sql &&
  ID_TEST_DB_HOST=127.0.0.1 ID_TEST_DB_PORT=$P ID_TEST_REDIS=127.0.0.1:$R PGPASSWORD=pg go test -p 1 -race ./...

docker rm -f id-pg-$P id-redis-$R
```

Test variables: `ID_TEST_DB_HOST`, `ID_TEST_DB_PORT` (5432), `ID_TEST_DB_NAME` (id_test; the app
role is `id`/`id`), `ID_TEST_REDIS` (`host:port`), `ID_TEST_REDIS_DB` (15), and `PGPASSWORD` (the
`postgres` superuser, only for `TestPeerTubeLinkerSQL`). With `-v`, nothing should say `SKIP`.

To look at a page: those that need no services (`/`, `/release-notes`, error pages) render with
`unitServer(t)` and `httptest.NewRecorder`; the consent and logout pages only in the flow tests,
where `e.get(b, "/authorize", authParams(...))` returns the consent HTML (write it to a file to open it).

## Map

| File | What |
|---|---|
| `main.go` | config from env (`loadConfig`, validation, `ID_ROLE_GROUPS`), wiring, HTTP timeouts |
| `server.go` | routes, CSP and security headers, cookies (`__Host-`), sessions, `sameSite`, views |
| `clients.go` | the clients file: `parseClients` (all validation), `checkRedirect`, `checkSecret`, exact `allowsRedirect` |
| `oidc.go` | discovery, JWKS, `/authorize` (`handleAuthorize`), `continueAuth`, `/consent`, `issueCode` |
| `login.go` | the round trip to the instance: `startLogin`, `/callback` (revokes the person's token) |
| `token.go` | account status cache (`person`), token families, replay, rate limit, `/token`, `/userinfo`, `/logout`, claims (`claimsOf`) |
| `state.go` | Redis key prefixes, every TTL, the `grant`/`session`/`authRequest` types, `kv` (`take` = GETDEL) |
| `mastodon.go` | instance API client; `person.refusal` (who may sign in) |
| `keys.go`, `crypto.go` | RS256 sign/verify, JWKS, key rotation; random tokens, `hashID`, constant-time `equal`, `s256` |
| `store.go` | consents and the audit log (`auditText` strips control chars, 200 chars) |
| `link.go` | PeerTube account linking (`docs/account-linking.md`) |
| `i18n.go` | every text, in `en` and `pt-BR`; `templates/`, `assets/` (CSS, fonts) |
| `version.go`, `internal/relnotes` | `VERSION` + build, `CHANGELOG.md` as `/release-notes` |

Tests: `unit_test.go` (no services: clients file `testClientsJSON`, keys, discovery, authorize
errors, `TestRefusal`, i18n, CSP), `flow_test.go` (`fakeMastodon`, `newTestEnv`, end-to-end flows:
`TestFullFlow`, `TestPKCE`, `TestClientAuthentication`, `TestConsentCSRF`, `TestRefusedAccounts`,
`TestSuspensionEndsAccess`, `TestPromptNoneAndLogout`), `security_test.go` (one regression test
per review finding), `link_test.go` (`TestLinkOfferFlow`, `TestPeerTubeLinkerSQL` with the real grants).

## Rules that must hold

A change that weakens one of these is a bug, even if no test catches it yet.
1. **Redirects only to registered URIs, compared exactly.** Until client and `redirect_uri` are
   validated, errors render a page (`handleAuthorize`); no fragments, http only on loopback for
   `dev` clients (`checkRedirect`). Logout redirects only to the client's `post_logout_redirect_uris`.
   Tests: `TestAuthorizeNeverRedirectsToUnregisteredURI`, `TestAuthorizeErrorsRedirect`, `TestLoopbackNeedsDev`.
2. **Codes are single use and bound.** GETDEL via `consumeScript`; bound to client, redirect URI,
   PKCE (S256 only, 43-char challenge) and nonce; public clients need PKCE; confidential ones PKCE
   or nonce unless `allow_no_pkce_or_nonce`. Tests: `TestPKCE`, `TestAuthorizeHardening`,
   `TestClientAuthentication`, `TestLegacyClientWithoutPKCEOrNonce`, `TestAllowNoPKCEOrNonceConfig`.
3. **Replay revokes the family.** A reused code or rotated refresh token revokes every token of its
   family; refresh stores successors before consuming the old token. Tests: `TestCodeReplayRevokesFamily`,
   `TestRefreshReuseRevokesFamily`, `TestRotationFailureKeepsToken`, `TestCodeIssuedBeforeLogout`.
4. **Only allowed accounts.** `person.refusal` (remote, suspended, disabled, unapproved, unconfirmed,
   no e-mail, silenced if configured) is checked at callback, authorize, consent, token, refresh
   (status at most 1 minute old) and userinfo. Tests: `TestRefusal`, `TestRefusedAccounts`, `TestSuspensionEndsAccess`.
5. **Secrets are never stored or logged in clear.** Redis keys are `hashID` of the value; client
   secrets are compared as SHA-256 in constant time; the audit log has no tokens, codes, secrets or
   IPs; the person's Mastodon token is revoked right after `whoami`. Never log a request body or header.
6. **State changes need proof.** Consent and logout POSTs need `Sec-Fetch-Site` same-origin (or
   absent) plus the session CSRF token; the consent request is bound to the account that saw it;
   a plain logout link only shows a confirmation; a hint without a session revokes only its `sid`.
   Tests: `TestConsentCSRF`, `TestLogoutRevokesRefreshTokens`, `TestLogoutHintWithoutSession`, `TestIndexSignOutForm`.
7. **Claims by scope only.** `groups`/`role` only from `ID_ROLE_GROUPS`, never raw role names;
   `sub` is the account id. Tests: `TestRoleGroupsMapping`, `TestLowercaseUsernameClient`, `TestFullFlow`.
8. **Fail closed.** A Redis error refuses (the rate limiter never fails open); an instance failure
   answers 503 and keeps the refresh token; only Mastodon's JSON 404 means "account gone".
   Tests: `TestRateLimiter`, `TestRefreshKeepsTokenOnUpstreamFailure`, `TestAdmin404`, `TestNegativeCache`.
9. **Bounded input.** Bodies 64 KiB (`maxFormBody`), state 512, nonce 255, repeated parameters refused,
   instance responses 256 KiB, HTTP timeouts in `main.go`. Keep new inputs bounded the same way.
10. **No inline script or style.** CSP `default-src 'none'`; CSS in `assets/`; only the consent and
    logout pages add an origin to `form-action`. Test: `TestNoInlineScriptOrStyle`.
11. **Both languages.** Every key of `translations` in `en` and `pt-BR` (`TestTranslationsHaveSameKeys`).

## The usual change (a claim, a client option, a check)

0. **Check it is not there already**: the README's Claims and clients-file sections, `claimsOf`,
   the `client` struct, `supportedScopes`/`claimsSupported` in `oidc.go`.
1. Client option: field on `client` (the decoder refuses unknown fields), validate it in
   `parseClients`, add it to `clients.example.json` and the README. Claim: `userClaims` +
   `claimsOf` behind a scope, listed in `claimsSupported`, shown on the consent page (`shares`).
2. New text: both languages in `i18n.go`. New Redis state: prefix and TTL in `state.go`, key = `hashID`.
3. Test the refusal cases, not only the happy path: wrong client, other account, replay, a refused account.
4. `gofmt`, `go vet`, the full suite with services and `-race`.

## Releasing

- `VERSION` holds `X.Y.Z`; CI adds the pipeline number (`X.Y.Z-BUILD`); a local build is `X.Y.Z-dev`.
- Every version needs its `CHANGELOG.md` entry (`TestChangelogHasVersion`); it is also `/release-notes`.
- A schema change goes in `schema.sql` (idempotent, run by the owner) and says so in the changelog.
- Code, comments, commits and the README in English. Small commits whose message says why.

## Security checks

CI runs gofmt, vet, the tests against PostgreSQL 17 and Redis 7.4, govulncheck, and the shared
scanners (gitleaks, trivy blocking; semgrep, gosec, hadolint, yamllint, poutine informative).
Scanners do not see protocol mistakes: review every change to `oidc.go`, `token.go`, `login.go`,
`clients.go` or `keys.go` against OpenID Connect Core and RFC 9700, and add a regression test to
`security_test.go` for each finding.
