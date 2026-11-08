package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeMastodon is the instance: OAuth with PKCE, verify_credentials, revoke and
// the admin accounts API. Whoever "signs in" is loginAs.
type fakeMastodon struct {
	mu       sync.Mutex
	loginAs  string
	accounts map[string]map[string]any // admin API entities by id
	codes    map[string][2]string      // code -> challenge, account id
	tokens   map[string]string         // token -> account id
	revoked  []string
	logins   int // times /oauth/authorize was hit
	lastAuth url.Values
	// Admin API behaviour: calls made, a forced status with its body, a delay.
	adminCalls  int
	adminStatus int
	adminBody   string
	adminDelay  time.Duration
}

const (
	mastoClientID = "masto-id"
	mastoSecret   = "masto-secret"
	adminToken    = "admin-token"
)

func adminEntity(id, username string) map[string]any {
	return map[string]any{
		"id": id, "username": username, "domain": nil, "email": username + "@mail.example", "confirmed": true, "approved": true,
		"disabled": false, "suspended": false, "silenced": false, "role": map[string]any{"name": ""},
		"account": map[string]any{"id": id, "username": username, "display_name": strings.ToUpper(username),
			"url": "https://example.social/@" + username, "avatar": "https://example.social/a/" + id + ".png"},
	}
}

func newFakeMastodon(t *testing.T) (*fakeMastodon, *httptest.Server) {
	f := &fakeMastodon{accounts: map[string]map[string]any{}, codes: map[string][2]string{}, tokens: map[string]string{}}
	f.accounts["109"] = adminEntity("109", "ana")
	f.accounts["109"]["role"] = map[string]any{"id": "2", "name": "Moderator"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.logins++
		f.lastAuth = q
		if q.Get("client_id") != mastoClientID || q.Get("scope") != "profile" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad authorize", 400)
			return
		}
		code := randomToken()
		f.codes[code] = [2]string{q.Get("code_challenge"), f.loginAs}
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		c, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		if !ok || r.PostForm.Get("client_secret") != mastoSecret || s256(r.PostForm.Get("code_verifier")) != c[0] {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		tok := randomToken()
		f.tokens[tok] = c[1]
		json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": "Bearer"})
	})
	mux.HandleFunc("GET /api/v1/accounts/verify_credentials", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id, ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			http.Error(w, "{}", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id": id, "username": "x"})
	})
	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.revoked = append(f.revoked, r.PostForm.Get("token"))
		delete(f.tokens, r.PostForm.Get("token"))
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("GET /api/v1/admin/accounts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+adminToken {
			http.Error(w, "{}", 403)
			return
		}
		f.mu.Lock()
		f.adminCalls++
		delay, status, body := f.adminDelay, f.adminStatus, f.adminBody
		f.mu.Unlock()
		time.Sleep(delay)
		if status != 0 {
			http.Error(w, body, status)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		a, ok := f.accounts[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"error":"Record not found"}`, 404)
			return
		}
		json.NewEncoder(w).Encode(a)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeMastodon) admin(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adminStatus, f.adminBody = status, body
}

func (f *fakeMastodon) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adminCalls
}

func (f *fakeMastodon) set(id, field string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[id][field] = v
}

type testEnv struct {
	// auditFrom is the newest audit_log id when the env was made: audit_log is
	// never cleaned, so auditCount only sees this test's rows.
	auditFrom int64
	t         *testing.T
	f         *fakeMastodon
	s         *server
	app       *httptest.Server
	rdb       *redis.Client
	jwks      []jwk
}

// testDBName is the database the tests use (ID_TEST_DB_NAME, default id_test).
// They delete its consents and drop and create schemas in it, so they refuse a
// name that doesn't end in _test: never point them at a real database.
func testDBName(t *testing.T) string {
	t.Helper()
	name := env("ID_TEST_DB_NAME", "id_test")
	if !strings.HasSuffix(name, "_test") {
		t.Fatalf("ID_TEST_DB_NAME=%q: the tests delete data, so the database name must end in _test", name)
	}
	return name
}

// testRedisDB is the Redis database index the tests flush (ID_TEST_REDIS_DB,
// default 15). The app always uses index 0, so the tests refuse it.
func testRedisDB(t *testing.T) int {
	t.Helper()
	n, err := strconv.Atoi(env("ID_TEST_REDIS_DB", "15"))
	if err != nil || n < 1 || n > 15 {
		t.Fatalf("ID_TEST_REDIS_DB must be 1 to 15 (the tests flush it; the app uses 0)")
	}
	return n
}

// newTestEnv needs Postgres and Redis: set ID_TEST_DB_HOST and ID_TEST_REDIS.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dbHost, addr := os.Getenv("ID_TEST_DB_HOST"), os.Getenv("ID_TEST_REDIS")
	if dbHost == "" || addr == "" {
		t.Skip("ID_TEST_DB_HOST and ID_TEST_REDIS not set")
	}
	f, inst := newFakeMastodon(t)
	f.loginAs = "109"
	var handler http.Handler
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(app.Close)
	cfg := config{issuer: app.URL, instance: inst.URL, domain: "example.social", lang: "en", allowSilenced: true,
		roleGroups: map[string]string{"2": "moderator"},
		sessionTTL: 12 * time.Hour, refreshTTL: 24 * time.Hour,
		dbHost: dbHost, dbPort: env("ID_TEST_DB_PORT", "5432"), dbUser: "id", dbPassword: "id", dbName: testDBName(t), dbSSLMode: "disable"}
	ctx := context.Background()
	db, err := openStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.pool.Close)
	if err := db.check(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, `DELETE FROM consents`); err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: testRedisDB(t)})
	t.Cleanup(func() { rdb.Close() })
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	clients, err := parseClients([]byte(testClientsJSON), os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	api := &mastodon{base: inst.URL, clientID: mastoClientID, clientSecret: mastoSecret, redirect: app.URL + "/callback",
		adminToken: adminToken, client: inst.Client()}
	s := newServer(cfg, tmpl, api, db, rdb, testKeySet(t), clients)
	handler = s.routes()
	e := &testEnv{t: t, f: f, s: s, app: app, rdb: rdb}
	e.auditFrom = e.auditMark()
	return e
}

// browser keeps cookies and stops at the clients' redirect URIs.
func (e *testEnv) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:       jar,
		Transport: e.app.Client().Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if h := req.URL.Hostname(); h != "127.0.0.1" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (e *testEnv) get(b *http.Client, path string, q url.Values) (*http.Response, string) {
	e.t.Helper()
	resp, err := b.Get(e.app.URL + path + "?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

var hiddenRe = regexp.MustCompile(`name="(csrf|request|link)" value="([^"]+)"`)

// consent submits the consent form found in a page.
func (e *testEnv) consent(b *http.Client, page, decision string) *http.Response {
	e.t.Helper()
	form := url.Values{"decision": {decision}}
	for _, m := range hiddenRe.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], m[2])
	}
	if form.Get("csrf") == "" || form.Get("request") == "" {
		e.t.Fatalf("no consent form in page:\n%s", page)
	}
	req, _ := http.NewRequest("POST", e.app.URL+"/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// redirected reads the parameters of a redirect to a client.
func redirected(t *testing.T, resp *http.Response, prefix string) url.Values {
	t.Helper()
	loc := resp.Header.Get("Location")
	if resp.StatusCode/100 != 3 || !strings.HasPrefix(loc, prefix+"?") {
		t.Fatalf("want redirect to %s, got %d %q", prefix, resp.StatusCode, loc)
	}
	u, _ := url.Parse(loc)
	return u.Query()
}

func authParams(client, redirect, verifier, scope string) url.Values {
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {scope},
		"state": {"state-" + client}, "nonce": {"nonce-" + client}}
	if verifier != "" {
		q.Set("code_challenge", s256(verifier))
		q.Set("code_challenge_method", "S256")
	}
	return q
}

func (e *testEnv) token(form url.Values, user, pass string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.app.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
	}
	resp, err := e.app.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *testEnv) userinfo(token string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.app.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := e.app.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// verifyIDToken checks the signature against the published JWKS, like a client would.
func (e *testEnv) verifyIDToken(tok string) map[string]any {
	e.t.Helper()
	resp, err := e.app.Client().Get(e.app.URL + "/jwks.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var set struct{ Keys []jwk }
	json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		e.t.Fatalf("not a JWS: %q", tok)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h struct{ Alg, Kid string }
	json.Unmarshal(hb, &h)
	i := slices.IndexFunc(set.Keys, func(k jwk) bool { return k.Kid == h.Kid })
	if h.Alg != "RS256" || i < 0 {
		e.t.Fatalf("header %+v not in JWKS", h)
	}
	nb, _ := base64.RawURLEncoding.DecodeString(set.Keys[i].N)
	eb, _ := base64.RawURLEncoding.DecodeString(set.Keys[i].E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		e.t.Fatalf("id_token signature: %v", err)
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(pb, &claims)
	return claims
}

// auditMark is the newest audit_log id now. Look only at rows after a mark
// (id > mark), never at "the newest row" or totals: audit_log keeps every run.
func (e *testEnv) auditMark() int64 {
	var id int64
	if err := e.s.db.pool.QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// auditCount counts this test's audit rows (after auditFrom) of an event and account.
func (e *testEnv) auditCount(event, account string) int {
	var n int
	if err := e.s.db.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE id > $1 AND event = $2 AND account_id = $3`,
		e.auditFrom, event, account).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestFullFlow(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	before := e.auditCount("login", "109")
	verifier := randomToken()
	resp, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid profile email"))
	if resp.StatusCode != 200 || !strings.Contains(page, "Tool") || !strings.Contains(page, "@ana@example.social") {
		t.Fatalf("consent page: %d\n%s", resp.StatusCode, page)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://client.example;") {
		t.Fatalf("consent CSP: %s", csp)
	}
	if len(e.f.revoked) != 1 {
		t.Fatalf("the instance token wasn't revoked: %v", e.f.revoked)
	}
	q := redirected(t, e.consent(b, page, "allow"), "https://client.example/cb")
	if q.Get("state") != "state-tool" || q.Get("iss") != e.app.URL || q.Get("code") == "" {
		t.Fatalf("callback params: %v", q)
	}
	code := q.Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}
	st, tok := e.token(form, "tool", testSecret)
	if st != 200 || tok["token_type"] != "Bearer" || tok["refresh_token"] != nil {
		t.Fatalf("token: %d %v", st, tok)
	}
	claims := e.verifyIDToken(tok["id_token"].(string))
	want := map[string]any{"iss": e.app.URL, "aud": "tool", "sub": "109", "nonce": "nonce-tool", "preferred_username": "ana", "name": "ANA",
		"email": "ana@mail.example", "email_verified": true, "role": "moderator", "profile": "https://example.social/@ana"}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("id_token %s = %v, want %v", k, claims[k], v)
		}
	}
	if exp := int64(claims["exp"].(float64)); exp-time.Now().Unix() > int64(idTokenTTL.Seconds())+5 || claims["auth_time"] == nil {
		t.Errorf("exp/auth_time: %v", claims)
	}
	st, info := e.userinfo(tok["access_token"].(string))
	if st != 200 || info["sub"] != "109" || info["email"] != "ana@mail.example" || fmt.Sprint(info["groups"]) != "[moderator]" {
		t.Fatalf("userinfo: %d %v", st, info)
	}
	if st, _ := e.userinfo("nope"); st != 401 {
		t.Fatalf("userinfo with a bad token: %d", st)
	}

	// A code works once.
	if st, out := e.token(form, "tool", testSecret); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reused code: %d %v", st, out)
	}

	// Same browser, second time: no new sign-in on the instance and no consent.
	logins := e.f.logins
	resp, _ = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", randomToken(), "openid profile"))
	if q := redirected(t, resp, "https://client.example/cb"); q.Get("code") == "" || e.f.logins != logins {
		t.Fatalf("second authorization: %v, logins %d -> %d", q, logins, e.f.logins)
	}
	// Another tool: no new sign-in, but its own consent.
	resp, page = e.get(b, "/authorize", authParams("other", "https://other.example/cb", "", "openid email"))
	if resp.StatusCode != 200 || !strings.Contains(page, "Other") || e.f.logins != logins {
		t.Fatalf("other tool: %d, logins %d -> %d", resp.StatusCode, logins, e.f.logins)
	}
	// More scopes than allowed before: consent again.
	resp, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", randomToken(), "openid profile email offline_access"))
	if resp.StatusCode != 200 || !strings.Contains(page, "access that continues") {
		t.Fatalf("broader scope should ask again: %d", resp.StatusCode)
	}
	if got := e.auditCount("login", "109") - before; got != 2 {
		t.Errorf("audit logins: %d", got)
	}
}

func TestDeny(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	q := redirected(t, e.consent(b, page, "deny"), "https://client.example/cb")
	if q.Get("error") != "access_denied" || q.Get("state") != "state-tool" || q.Get("code") != "" {
		t.Fatalf("deny: %v", q)
	}
}

// The consent form needs the CSRF token of the session that saw it, and only
// same-origin posts.
func TestConsentCSRF(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	forged := regexp.MustCompile(`name="csrf" value="[^"]+"`).ReplaceAllString(page, `name="csrf" value="forged"`)
	if resp := e.consent(b, forged, "allow"); resp.StatusCode != 403 {
		t.Fatalf("bad csrf: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", e.app.URL+"/consent", strings.NewReader("decision=allow"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, _ := b.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site post: %d", resp.StatusCode)
	}
	// Another browser (no session) can't use the form either.
	if resp := e.consent(e.browser(), page, "allow"); resp.StatusCode != 403 {
		t.Fatalf("form from another browser: %d", resp.StatusCode)
	}
}

func TestPKCE(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	// A public client without PKCE goes back with an error, before any sign-in.
	resp, _ := e.get(b, "/authorize", authParams("spa", "https://spa.example/cb", "", "openid"))
	if q := redirected(t, resp, "https://spa.example/cb"); q.Get("error") != "invalid_request" || e.f.logins != 0 {
		t.Fatalf("public without PKCE: %v", q)
	}
	verifier := randomToken()
	_, page := e.get(b, "/authorize", authParams("spa", "https://spa.example/cb", verifier, "openid"))
	code := redirected(t, e.consent(b, page, "allow"), "https://spa.example/cb").Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://spa.example/cb"}, "client_id": {"spa"}, "code_verifier": {randomToken()}}
	if st, out := e.token(form, "", ""); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", st, out)
	}
	// The code is gone after a failed attempt too.
	form.Set("code_verifier", verifier)
	if st, _ := e.token(form, "", ""); st != 400 {
		t.Fatalf("code reused after a failure: %d", st)
	}
	// Right verifier on a new code works, with no secret.
	resp, _ = e.get(b, "/authorize", authParams("spa", "https://spa.example/cb", verifier, "openid"))
	form.Set("code", redirected(t, resp, "https://spa.example/cb").Get("code"))
	if st, out := e.token(form, "", ""); st != 200 || out["id_token"] == nil {
		t.Fatalf("public token: %d %v", st, out)
	}
	// A confidential client that sent a challenge must send the verifier.
	_, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid"))
	code = redirected(t, e.consent(b, page, "allow"), "https://client.example/cb").Get("code")
	form = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}}
	if st, out := e.token(form, "tool", testSecret); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("missing verifier: %d %v", st, out)
	}
}

func TestClientAuthentication(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	newCode := func() string {
		resp, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
		if resp.StatusCode == 200 {
			resp = e.consent(b, page, "allow")
		}
		return redirected(t, resp, "https://client.example/cb").Get("code")
	}
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}}
	}
	if st, out := e.token(form(newCode()), "tool", "wrong-secret"); st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", st, out)
	}
	if st, _ := e.token(form(newCode()), "", ""); st != 401 {
		t.Fatalf("no authentication: %d", st)
	}
	// Another registered client can't redeem the code.
	if st, out := e.token(form(newCode()), "other", testSecret+"x"); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code of another client: %d %v", st, out)
	}
	// The redirect_uri must match.
	f := form(newCode())
	f.Set("redirect_uri", "https://client.example/other")
	if st, _ := e.token(f, "tool", testSecret); st != 400 {
		t.Fatalf("other redirect_uri: %d", st)
	}
	// client_secret_post works.
	f = form(newCode())
	f.Set("client_id", "tool")
	f.Set("client_secret", testSecret)
	if st, out := e.token(f, "", ""); st != 200 || out["id_token"] == nil {
		t.Fatalf("client_secret_post: %d %v", st, out)
	}
	// Both methods at once are refused.
	f = form(newCode())
	f.Set("client_secret", testSecret)
	if st, _ := e.token(f, "tool", testSecret); st != 401 {
		t.Fatalf("two methods: %d", st)
	}
}

func TestRefusedAccounts(t *testing.T) {
	for name, c := range map[string]struct {
		field string
		value any
		key   string
	}{
		"suspended":   {"suspended", true, "sign in here"},
		"disabled":    {"disabled", true, "sign in here"},
		"unapproved":  {"approved", false, "needs to be approved"},
		"unconfirmed": {"confirmed", false, "needs to be approved"},
		"remote":      {"domain", "elsewhere.example", "sign in here"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			e.f.set("109", c.field, c.value)
			b := e.browser()
			resp, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
			if resp.StatusCode != 403 || !strings.Contains(page, c.key) {
				t.Fatalf("%d\n%s", resp.StatusCode, page)
			}
			u, _ := url.Parse(e.app.URL)
			for _, ck := range b.Jar.Cookies(u) {
				if ck.Name == sessionCookie {
					t.Fatal("a refused account got a session")
				}
			}
			if e.auditCount("refused", "109") == 0 {
				t.Fatal("refusal not audited")
			}
		})
	}
	t.Run("unknown account", func(t *testing.T) {
		e := newTestEnv(t)
		e.f.loginAs = "404"
		resp, _ := e.get(e.browser(), "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
		if resp.StatusCode != 403 {
			t.Fatalf("%d", resp.StatusCode)
		}
	})
	t.Run("silenced", func(t *testing.T) {
		e := newTestEnv(t)
		e.f.set("109", "silenced", true)
		if resp, _ := e.get(e.browser(), "/authorize", authParams("tool", "https://client.example/cb", "", "openid")); resp.StatusCode != 200 {
			t.Fatalf("silenced allowed by default: %d", resp.StatusCode)
		}
		e.s.cfg.allowSilenced = false
		if resp, _ := e.get(e.browser(), "/authorize", authParams("tool", "https://client.example/cb", "", "openid")); resp.StatusCode != 403 {
			t.Fatalf("silenced with ID_ALLOW_SILENCED=false: %d", resp.StatusCode)
		}
	})
}

// A suspension after sign-in ends access at the next authorization (once the
// short cache expires), at userinfo and at refresh.
func TestSuspensionEndsAccess(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	verifier := randomToken()
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid offline_access"))
	code := redirected(t, e.consent(b, page, "allow"), "https://client.example/cb").Get("code")
	st, tok := e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}, "tool", testSecret)
	if st != 200 || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", st, tok)
	}
	// Refresh works and rotates.
	st, tok2 := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}, "tool", testSecret)
	if st != 200 || tok2["refresh_token"] == tok["refresh_token"] || tok2["id_token"] == nil {
		t.Fatalf("refresh: %d %v", st, tok2)
	}
	if st, _ := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}, "tool", testSecret); st != 400 {
		t.Fatalf("old refresh token reused: %d", st)
	}
	e.f.set("109", "suspended", true)
	// Refresh asks the instance directly.
	if st, out := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2["refresh_token"].(string)}}, "tool", testSecret); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh of a suspended account: %d %v", st, out)
	}
	e.rdb.Del(context.Background(), personKey+"109") // the cache expires
	if st, _ := e.userinfo(tok2["access_token"].(string)); st != 401 {
		t.Fatalf("userinfo of a suspended account: %d", st)
	}
	resp, _ := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", randomToken(), "openid"))
	if resp.StatusCode != 403 {
		t.Fatalf("authorize of a suspended account: %d", resp.StatusCode)
	}
}

func TestPromptNoneAndLogout(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	q := authParams("tool", "https://client.example/cb", "", "openid")
	q.Set("prompt", "none")
	resp, _ := e.get(b, "/authorize", q)
	if got := redirected(t, resp, "https://client.example/cb"); got.Get("error") != "login_required" {
		t.Fatalf("prompt=none without session: %v", got)
	}
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	// Signed in but no consent yet.
	resp, _ = e.get(b, "/authorize", q)
	if got := redirected(t, resp, "https://client.example/cb"); got.Get("error") != "consent_required" {
		t.Fatalf("prompt=none without consent: %v", got)
	}
	_, page = e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	code := redirected(t, e.consent(b, page, "allow"), "https://client.example/cb").Get("code")
	_, tok := e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}}, "tool", testSecret)
	resp, _ = e.get(b, "/authorize", q)
	if got := redirected(t, resp, "https://client.example/cb"); got.Get("code") == "" {
		t.Fatalf("prompt=none with session and consent: %v", got)
	}
	// Unregistered post-logout URI: a page, no redirect.
	resp, _ = e.get(e.browser(), "/logout", url.Values{"id_token_hint": {tok["id_token"].(string)}, "post_logout_redirect_uri": {"https://evil.example/"}})
	if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered logout redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Registered one, named by the id_token_hint.
	resp, _ = e.get(b, "/logout", url.Values{"id_token_hint": {tok["id_token"].(string)}, "post_logout_redirect_uri": {"https://client.example/bye"}, "state": {"s1"}})
	if got := redirected(t, resp, "https://client.example/bye"); got.Get("state") != "s1" {
		t.Fatalf("logout redirect: %v", got)
	}
	// The session is gone: prompt=none needs a sign-in again.
	resp, _ = e.get(b, "/authorize", q)
	if got := redirected(t, resp, "https://client.example/cb"); got.Get("error") != "login_required" {
		t.Fatalf("after logout: %v", got)
	}
	if e.auditCount("logout", "109") == 0 {
		t.Fatal("logout not audited")
	}
}

// The state cookie binds the instance callback to the browser that started it.
func TestCallbackNeedsStateCookie(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasSuffix(loc.Path, "/oauth/authorize") {
		t.Fatalf("not sent to the instance: %v", loc)
	}
	// Someone else's browser opens the callback with a valid state.
	other := e.browser()
	resp, _ = e.get(other, "/callback", url.Values{"code": {"x"}, "state": {loc.Query().Get("state")}})
	if resp.StatusCode != 400 {
		t.Fatalf("callback without the state cookie: %d", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	e := newTestEnv(t)
	resp, err := e.app.Client().Get(e.app.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, resp)
	}
}
