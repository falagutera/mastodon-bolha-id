# Account linking

Some tools refuse to sign in an existing password account through an external
provider. PeerTube does: its core finds the account by e-mail, sees it was created
with a password (`pluginAuth` is empty) and answers "invalid credentials". It never
links on its own, on purpose.

For a client with `"account_link": "peertube"`, id looks for such an account when
someone signs in and, if there is one, shows it on the consent page:

> You already have an account on bolha.tube. The account @ana on bolha.tube uses the
> same e-mail as your bolha.us account. To sign in to it through bolha.us, it has to
> be linked. [Link and sign in] [Deny]

"Link and sign in" sets the account's `pluginAuth` to the auth plugin and
`pluginAuthExternalId` to the person's `sub`, ends its open sessions and goes on with
the sign-in. From then on the account signs in only through id; its PeerTube password
stops working. Deny changes nothing.

## Rules

- Only an account whose e-mail equals the person's **confirmed** e-mail on the
  instance (case-insensitive). Whoever controls that inbox could already take the
  account over with PeerTube's "forgot password", so linking grants nothing new.
- Only ordinary accounts: role User, not blocked, not linked yet. Admins and
  moderators, and two accounts with the same e-mail, are left to the admins.
- Everything is checked again when the form is sent, inside the update itself, and
  the form must name the same account the page showed.
- With `prompt=none` there is no page, so no offer.
- A failure to reach PeerTube's database only means no offer; sign-in goes on.
- Each link is in the audit log (`link`, with the PeerTube username).
- Undoing it is for the admins (set `pluginAuth` back to NULL), so people don't
  flip between the two ways of signing in.

## Database role

id connects with a role that can do only this:

```sql
CREATE ROLE id_link_peertube LOGIN NOINHERIT CONNECTION LIMIT 4 PASSWORD '...';
GRANT CONNECT ON DATABASE peertube TO id_link_peertube;
GRANT USAGE ON SCHEMA public TO id_link_peertube;
GRANT SELECT (id, username, email, role, blocked, "pluginAuth") ON public."user" TO id_link_peertube;
GRANT UPDATE ("pluginAuth", "pluginAuthExternalId") ON public."user" TO id_link_peertube;
GRANT SELECT ("userId"), DELETE ON public."oAuthToken" TO id_link_peertube;
```

It can't read password hashes, tokens or anything else, nor change roles or e-mails.
`TestPeerTubeLinkerSQL` runs the real queries as a role with exactly these grants.

Then set `ID_LINK_PEERTUBE_DSN`, such as
`postgres://id_link_peertube:...@db.internal:5432/peertube?sslmode=require`.

## PeerTube side

- The auth plugin is `peertube-plugin-auth-openid-connect` (2.x), with
  `external-id-property` = `sub`.
- PeerTube usernames are lower case only: register the client with
  `"lowercase_username": true`.
- Checked against PeerTube 8.3 (`server/core/lib/auth/oauth-user.ts`). The test
  table mirrors the columns used; review them on PeerTube upgrades.
