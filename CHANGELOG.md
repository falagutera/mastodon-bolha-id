# Changelog

All notable changes to id. Versions follow [SemVer](https://semver.org/); images are
published as `registry.gutocarvalho.net/images/id:<version>-<build>`.

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
