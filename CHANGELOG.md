# Changelog

All notable changes to id. Versions follow [SemVer](https://semver.org/); images are
published as `registry.gutocarvalho.net/images/id:<version>-<build>`.

## 0.2.1 — 2026-11-08

From the security review (scanners, code review and a Strix pass, which found no exploitable issue):

- Linking reads the account fresh from the instance when the form is sent, so a just-changed or unconfirmed e-mail can't be used.
- When the person already has another account in the tool linked here, the page says so (PeerTube allows one per person) instead of "temporarily unavailable".

## 0.2.0 — 2026-11-08

- Account linking with PeerTube: for a client with `"account_link": "peertube"`, the consent page offers to link the person's existing password account there (same e-mail as their confirmed one on the instance), so they solve it themselves instead of hitting "invalid credentials". Ordinary accounts only; admins and moderators stay with the admins. Uses a database role that can only read a few columns and change the auth plugin of an account (`ID_LINK_PEERTUBE_DSN`, see docs/account-linking.md). Each link is in the audit log.

## 0.1.3 — 2026-11-08

- A client can ask for `preferred_username` in lower case (`"lowercase_username": true` in the clients file), for apps that only accept lower-case usernames, such as PeerTube. Other clients keep the username as it is on the instance.

## 0.1.2 — 2026-11-07

Hardening from the updated linters.

- The image declares the numeric distroless "nonroot" user (`USER 65532:65532`), so scanners and runtimes see a non-root user.

## 0.1.1 — 2026-11-06

- A confidential client can be allowed to sign in without PKCE or a nonce (`"allow_no_pkce_or_nonce": true` in the clients file), for RP libraries that only send `state`, such as passport-openidconnect 0.1.x used by Overleaf. Off by default, refused on public clients, logged as a warning at startup. PKCE or a nonce that the client does send is still checked.

## 0.1.0 — 2026-11-06

First version.

- OpenID Connect provider for one Mastodon instance: discovery, JWKS, authorization code flow with PKCE, token, userinfo and logout endpoints.
- Sign-in on the instance with its OAuth; only approved, confirmed and active local accounts get through, checked again on every authorization and refresh.
- `id_token` signed with RS256, with the account id as `sub`, plus name, @, avatar, profile link, confirmed e-mail and role.
- Consent page in Portuguese and English the first time an account uses a tool; the choice is remembered.
- Short session here (2 hours by default), so a second tool doesn't ask to sign in on the instance again.
- Optional refresh tokens (`offline_access`), single use and rotated. A replayed refresh token or authorization code revokes every token that came from the same code; signing out revokes the account's tokens.
- Refresh is rate limited per account and client and per client, keeps the refresh token when the instance fails, and stores the new tokens before consuming the old one; account lookups are cached and shared between concurrent requests.
- `sid` claim (the token family) in `id_token`s; sign-out with only a valid `id_token_hint` revokes just that family, and hints older than the refresh token lifetime are refused.
- Before release: independent security code review, two automated penetration test runs (Strix) and per-commit automated reviews; every finding fixed with a regression test. The README explains how the app is tested.
- `groups`/`role` claims only from an explicit mapping of instance role ids (`ID_ROLE_GROUPS`).
- Safer defaults: confidential clients need PKCE or a nonce, http loopback redirects only for `dev` clients, database TLS required, Redis password required.
- Audit log of sign-ins, consents, refusals and sign-outs, without tokens, with bounded and cleaned fields.
- Release notes page, and the same data at `/release-notes.json`.
