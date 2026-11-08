package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeLinker keeps candidates by e-mail; a linked one disappears, like on PeerTube.
type fakeLinker struct {
	mu     sync.Mutex
	byMail map[string]linkCandidate
	linked []string // "username email sub"
}

func (f *fakeLinker) find(_ context.Context, email string) (linkCandidate, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.byMail[strings.ToLower(email)]
	return c, ok, nil
}

func (f *fakeLinker) link(_ context.Context, c linkCandidate, email, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if got, ok := f.byMail[strings.ToLower(email)]; !ok || got != c {
		return errLinkGone
	}
	delete(f.byMail, strings.ToLower(email))
	f.linked = append(f.linked, c.Username+" "+email+" "+sub)
	return nil
}

func TestLinkOfferFlow(t *testing.T) {
	e := newTestEnv(t)
	fl := &fakeLinker{byMail: map[string]linkCandidate{"ana@mail.example": {ID: 7, Username: "ana_pt"}}}
	e.s.linkers["tool"] = fl
	b := e.browser()

	// Without the link field nothing is linked, even with the offer on screen.
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid email"))
	if !strings.Contains(page, `name="link" value="7"`) || !strings.Contains(page, "@ana_pt") || !strings.Contains(page, "Link and sign in") {
		t.Fatalf("no link offer:\n%s", page)
	}
	q := redirected(t, e.consent(b, strings.Replace(page, `name="link"`, `name="nolink"`, 1), "allow"), "https://client.example/cb")
	if q.Get("code") == "" || len(fl.linked) != 0 {
		t.Fatalf("allow without link: %v %v", q, fl.linked)
	}

	// Consent was given, but the offer still shows the page. A tampered id is refused.
	_, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid email"))
	if !strings.Contains(page, `name="link" value="7"`) {
		t.Fatalf("offer should show the consent page again:\n%s", page)
	}
	if resp := e.consent(b, strings.Replace(page, `name="link" value="7"`, `name="link" value="8"`, 1), "allow"); resp.StatusCode != http.StatusConflict || len(fl.linked) != 0 {
		t.Fatalf("tampered link id: %d %v", resp.StatusCode, fl.linked)
	}

	// Deny never links.
	_, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid email"))
	if q := redirected(t, e.consent(b, page, "deny"), "https://client.example/cb"); q.Get("error") != "access_denied" || len(fl.linked) != 0 {
		t.Fatalf("deny: %v %v", q, fl.linked)
	}

	// Link and sign in.
	before := e.auditCount("link", "109")
	_, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid email"))
	q = redirected(t, e.consent(b, page, "allow"), "https://client.example/cb")
	if q.Get("code") == "" || len(fl.linked) != 1 || fl.linked[0] != "ana_pt ana@mail.example 109" {
		t.Fatalf("link: %v %v", q, fl.linked)
	}
	if e.auditCount("link", "109") != before+1 {
		t.Error("link not audited")
	}

	// Nothing left to link: straight back to the tool.
	resp, _ := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid email"))
	if q := redirected(t, resp, "https://client.example/cb"); q.Get("code") == "" {
		t.Fatalf("after linking: %v", q)
	}

	// Other tools never see the offer.
	fl.byMail["ana@mail.example"] = linkCandidate{ID: 9, Username: "again"}
	if _, page := e.get(b, "/authorize", authParams("other", "https://other.example/cb", "", "openid email")); strings.Contains(page, `name="link"`) {
		t.Fatal("offer on a client without account_link")
	}
}

func TestAccountLinkConfig(t *testing.T) {
	ok := `{"clients":[{"id":"t","name":"T","secret_sha256":"` + sha256hex(testSecret) + `","account_link":"peertube","redirect_uris":["https://t.example/cb"]}]}`
	if cs, err := parseClients([]byte(ok), os.Getenv); err != nil || cs["t"].AccountLink != "peertube" {
		t.Fatalf("account_link peertube: %v", err)
	}
	bad := strings.Replace(ok, `"peertube"`, `"gitlab"`, 1)
	if _, err := parseClients([]byte(bad), os.Getenv); err == nil {
		t.Fatal("unknown account_link accepted")
	}
	// Without the DSN the client works, without the offer.
	s := unitServer(t)
	s.clients = clientList{"t": &client{ID: "t", AccountLink: "peertube"}}
	if err := s.setupLinkers(context.Background()); err != nil || s.linkers["t"] != nil {
		t.Fatalf("no DSN: %v %v", err, s.linkers)
	}
}

// TestPeerTubeLinkerSQL runs the real queries against a PeerTube-shaped table,
// as a role with only the grants the deployment gives (see docs/account-linking.md).
// Needs ID_TEST_DB_HOST and the postgres superuser password in PGPASSWORD.
func TestPeerTubeLinkerSQL(t *testing.T) {
	host, admin := os.Getenv("ID_TEST_DB_HOST"), os.Getenv("PGPASSWORD")
	if host == "" || admin == "" {
		t.Skip("ID_TEST_DB_HOST and PGPASSWORD not set")
	}
	port := env("ID_TEST_DB_PORT", "5432")
	ctx := context.Background()
	su, err := pgx.Connect(ctx, (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", admin), Host: net.JoinHostPort(host, port), Path: "/id", RawQuery: "sslmode=disable"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer su.Close(ctx)
	for _, q := range []string{
		`DROP SCHEMA IF EXISTS pt_test CASCADE`,
		`DROP ROLE IF EXISTS pt_link_test`,
		`CREATE SCHEMA pt_test`,
		`CREATE TABLE pt_test."user" (id serial PRIMARY KEY, username text NOT NULL, email text NOT NULL, password text,
		  role int NOT NULL DEFAULT 2, blocked boolean NOT NULL DEFAULT false, "pluginAuth" text, "pluginAuthExternalId" text)`,
		`CREATE TABLE pt_test."oAuthToken" (id serial PRIMARY KEY, "accessToken" text, "userId" int NOT NULL)`,
		`INSERT INTO pt_test."user" (username, email, password, role, blocked, "pluginAuth") VALUES
		  ('ana', 'Ana@Mail.example', 'h', 2, false, NULL),
		  ('boss', 'boss@mail.example', 'h', 0, false, NULL),
		  ('mod', 'mod@mail.example', 'h', 1, false, NULL),
		  ('gone', 'gone@mail.example', 'h', 2, true, NULL),
		  ('done', 'done@mail.example', NULL, 2, false, 'peertube-plugin-auth-openid-connect'),
		  ('twin1', 'twin@mail.example', 'h', 2, false, NULL),
		  ('twin2', 'TWIN@mail.example', 'h', 2, false, NULL),
		  ('bob', 'bob@mail.example', 'h', 2, false, NULL)`,
		`INSERT INTO pt_test."oAuthToken" ("accessToken", "userId") VALUES ('a1', 1), ('a2', 1), ('b1', 8)`,
		`CREATE ROLE pt_link_test LOGIN PASSWORD 'pt'`,
		`GRANT USAGE ON SCHEMA pt_test TO pt_link_test`,
		`GRANT SELECT (id, username, email, role, blocked, "pluginAuth") ON pt_test."user" TO pt_link_test`,
		`GRANT UPDATE ("pluginAuth", "pluginAuthExternalId") ON pt_test."user" TO pt_link_test`,
		`GRANT SELECT ("userId"), DELETE ON pt_test."oAuthToken" TO pt_link_test`,
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() {
		su.Exec(ctx, `DROP SCHEMA IF EXISTS pt_test CASCADE`) //nolint:errcheck
	})
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("pt_link_test", "pt"), Host: net.JoinHostPort(host, port), Path: "/id",
		RawQuery: "sslmode=disable&search_path=pt_test"}).String()
	l, err := openPeerTubeLinker(ctx, dsn, "peertube-plugin-auth-openid-connect")
	if err != nil {
		t.Fatal(err)
	}
	defer l.pool.Close()

	for mail, want := range map[string]bool{
		"ana@mail.example": true, "boss@mail.example": false, "mod@mail.example": false, "gone@mail.example": false,
		"done@mail.example": false, "twin@mail.example": false, "nobody@mail.example": false, "": false,
	} {
		c, ok, err := l.find(ctx, mail)
		if err != nil || ok != want {
			t.Errorf("find %q: %v %v %v", mail, c, ok, err)
		}
	}
	c, _, _ := l.find(ctx, "ANA@mail.example")
	if c.Username != "ana" {
		t.Fatalf("find is case-insensitive: %v", c)
	}
	// The e-mail must still match: no linking someone else's account by id.
	if err := l.link(ctx, linkCandidate{ID: 8, Username: "bob"}, "ana@mail.example", "109"); !errors.Is(err, errLinkGone) {
		t.Fatalf("link with another e-mail: %v", err)
	}
	if err := l.link(ctx, c, "ana@mail.example", "109"); err != nil {
		t.Fatal(err)
	}
	var plugin, ext string
	var tokens, others int
	su.QueryRow(ctx, `SELECT "pluginAuth", "pluginAuthExternalId" FROM pt_test."user" WHERE id = $1`, c.ID).Scan(&plugin, &ext)
	su.QueryRow(ctx, `SELECT count(*) FILTER (WHERE "userId" = 1), count(*) FILTER (WHERE "userId" <> 1) FROM pt_test."oAuthToken"`).Scan(&tokens, &others)
	if plugin != "peertube-plugin-auth-openid-connect" || ext != "109" || tokens != 0 || others != 1 {
		t.Fatalf("after link: plugin=%q ext=%q tokens=%d others=%d", plugin, ext, tokens, others)
	}
	// Twice: already linked.
	if err := l.link(ctx, c, "ana@mail.example", "109"); !errors.Is(err, errLinkGone) {
		t.Fatalf("second link: %v", err)
	}
	// The role can't touch anything else.
	lc, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close(ctx)
	for _, q := range []string{`SELECT password FROM "user"`, `UPDATE "user" SET role = 0`, `UPDATE "user" SET email = 'x'`, `SELECT "accessToken" FROM "oAuthToken"`} {
		if _, err := lc.Exec(ctx, q); err == nil {
			t.Errorf("role could run: %s", q)
		}
	}
}
