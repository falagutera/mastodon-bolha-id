package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// store keeps what must outlive Redis: consents and the audit log.
type store struct {
	pool *pgxpool.Pool
}

func openStore(ctx context.Context, c config) (*store, error) {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.dbUser, c.dbPassword),
		Host:     net.JoinHostPort(c.dbHost, c.dbPort),
		Path:     "/" + c.dbName,
		RawQuery: url.Values{"sslmode": {c.dbSSLMode}}.Encode(),
	}
	cfg, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		return nil, fmt.Errorf("database settings: %w", err)
	}
	cfg.MaxConns = 3
	// Simple protocol so it also works behind pgbouncer in transaction mode.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	return &store{pool: pool}, nil
}

// check fails at startup when schema.sql wasn't applied.
func (s *store) check(ctx context.Context) error {
	var n int
	return s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM consents WHERE false) + (SELECT count(*) FROM audit_log WHERE false)`).Scan(&n)
}

// consented tells whether the account already allowed every requested scope.
func (s *store) consented(ctx context.Context, accountID, clientID string, scopes []string) (bool, error) {
	var granted string
	err := s.pool.QueryRow(ctx, `SELECT scopes FROM consents WHERE account_id = $1 AND client_id = $2`, accountID, clientID).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	have := strings.Fields(granted)
	for _, sc := range scopes {
		if !slices.Contains(have, sc) {
			return false, nil
		}
	}
	return true, nil
}

// consent records the scopes, adding to what was allowed before.
func (s *store) consent(ctx context.Context, accountID, clientID string, scopes []string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO consents (account_id, client_id, scopes) VALUES ($1, $2, $3)
		ON CONFLICT (account_id, client_id) DO UPDATE SET scopes = (
		  SELECT string_agg(DISTINCT s, ' ' ORDER BY s) FROM unnest(string_to_array(consents.scopes || ' ' || $3, ' ')) AS s WHERE s <> ''
		), updated_at = now()`,
		accountID, clientID, strings.Join(scopes, " "))
	return err
}

// auditEntry is one line of the log. It never holds tokens, codes or secrets.
type auditEntry struct {
	AccountID string
	Acct      string
	ClientID  string
	Event     string // login, consent, deny, refused, refresh, logout
	Detail    string
}

func (s *store) audit(ctx context.Context, e auditEntry) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (account_id, acct, client_id, event, detail) VALUES ($1, $2, $3, $4, $5)`,
		auditText(e.AccountID), auditText(e.Acct), auditText(e.ClientID), auditText(e.Event), auditText(e.Detail))
	return err
}

const maxAuditField = 200

// auditText drops control characters and bounds the length of a log field.
func auditText(v string) string {
	var b strings.Builder
	n := 0
	for _, r := range v {
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		if n == maxAuditField {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
