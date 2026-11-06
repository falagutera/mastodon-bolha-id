# Changelog

All notable changes to id. Versions follow [SemVer](https://semver.org/); images are
published as `registry.gutocarvalho.net/images/id:<version>-<build>`.

## 0.1.0 — 2026-11-06

First version.

- OpenID Connect provider for one Mastodon instance: discovery, JWKS, authorization code flow with PKCE, token, userinfo and logout endpoints.
- Sign-in on the instance with its OAuth; only approved, confirmed and active local accounts get through, checked again on every authorization and refresh.
- `id_token` signed with RS256, with the account id as `sub`, plus name, @, avatar, profile link, confirmed e-mail and role.
- Consent page in Portuguese and English the first time an account uses a tool; the choice is remembered.
- Short session here, so a second tool doesn't ask to sign in on the instance again.
- Optional refresh tokens (`offline_access`), single use.
- Audit log of sign-ins, consents, refusals and sign-outs, without tokens.
- Release notes page, and the same data at `/release-notes.json`.
