-- Run once as the database owner, not as the app user. See README.md.
-- The app can't alter its own schema, and can't rewrite the audit log.

-- What each account allowed each client to receive. Scopes are space separated.
CREATE TABLE IF NOT EXISTS consents (
  account_id text NOT NULL,
  client_id  text NOT NULL,
  scopes     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, client_id)
);

-- Who signed in to which client, and when. Never tokens or codes.
CREATE TABLE IF NOT EXISTS audit_log (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  account_id text NOT NULL,
  acct       text NOT NULL DEFAULT '',
  client_id  text NOT NULL DEFAULT '',
  event      text NOT NULL,
  detail     text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_account_at ON audit_log (account_id, at DESC);
CREATE INDEX IF NOT EXISTS audit_log_client_at ON audit_log (client_id, at DESC);

-- Replace id with your app user if it has another name.
GRANT SELECT, INSERT, UPDATE, DELETE ON consents TO id;
GRANT SELECT, INSERT ON audit_log TO id;
