package main

// Account linking: some tools refuse to sign in an existing password account
// through an external provider (PeerTube does). For those, the consent page can
// offer to link it, so people solve it themselves. The rule: the tool account
// has the same e-mail as the person's confirmed e-mail on the instance. Whoever
// controls that inbox could already take the account over with "forgot
// password", so linking grants nothing new.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// linkCandidate is an account in a tool that can be linked.
type linkCandidate struct {
	ID       int64
	Username string
}

func (c linkCandidate) key() string { return strconv.FormatInt(c.ID, 10) }

// accountLinker finds and links one tool's existing password accounts.
type accountLinker interface {
	// find returns the one unlinked, ordinary account with this e-mail, if any.
	find(ctx context.Context, email string) (linkCandidate, bool, error)
	// link hands the account over to sign-in through here, for this subject.
	link(ctx context.Context, c linkCandidate, email, sub string) error
}

var errLinkGone = errors.New("account changed meanwhile")

const linkTimeout = 3 * time.Second

// peertubeLinker works on PeerTube's database with a role that can only read
// id, username, email, role, blocked and pluginAuth of "user", update
// pluginAuth/pluginAuthExternalId, and delete that person's oAuthToken rows.
type peertubeLinker struct {
	pool   *pgxpool.Pool
	plugin string // npm name of the auth plugin, e.g. peertube-plugin-auth-openid-connect
}

// peertubeRoleUser is PeerTube's UserRole.USER; admins (0) and moderators (1)
// are linked by hand only.
const peertubeRoleUser = 2

func openPeerTubeLinker(ctx context.Context, dsn, plugin string) (*peertubeLinker, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("peertube database settings: %w", err)
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("peertube database: %w", err)
	}
	return &peertubeLinker{pool: pool, plugin: plugin}, nil
}

func (l *peertubeLinker) find(ctx context.Context, email string) (linkCandidate, bool, error) {
	if email == "" {
		return linkCandidate{}, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, linkTimeout)
	defer cancel()
	rows, err := l.pool.Query(ctx,
		`SELECT id, username FROM "user"
		 WHERE lower(email) = lower($1) AND "pluginAuth" IS NULL AND role = $2 AND blocked = false
		 LIMIT 2`, email, peertubeRoleUser)
	if err != nil {
		return linkCandidate{}, false, err
	}
	found, err := pgx.CollectRows(rows, pgx.RowToStructByPos[linkCandidate])
	if err != nil || len(found) != 1 { // none, or ambiguous: offer nothing
		return linkCandidate{}, false, err
	}
	return found[0], true, nil
}

func (l *peertubeLinker) link(ctx context.Context, c linkCandidate, email, sub string) error {
	ctx, cancel := context.WithTimeout(ctx, linkTimeout)
	defer cancel()
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	// Every condition from find again: the account may have changed since.
	tag, err := tx.Exec(ctx,
		`UPDATE "user" SET "pluginAuth" = $1, "pluginAuthExternalId" = $2
		 WHERE id = $3 AND lower(email) = lower($4) AND "pluginAuth" IS NULL AND role = $5 AND blocked = false`,
		l.plugin, sub, c.ID, email, peertubeRoleUser)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errLinkGone
	}
	// Sessions opened with the password end now.
	if _, err := tx.Exec(ctx, `DELETE FROM "oAuthToken" WHERE "userId" = $1`, c.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// linkKinds are the values of "account_link" in the clients file.
var linkKinds = []string{"peertube"}
