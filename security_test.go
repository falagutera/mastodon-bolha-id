package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Regression tests for the security review of 0.1.0.

// signIn runs a full sign-in with offline_access and returns the tokens.
func (e *testEnv) signIn(b *http.Client) map[string]any {
	e.t.Helper()
	verifier := randomToken()
	resp, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid profile offline_access"))
	if resp.StatusCode == 200 {
		resp = e.consent(b, page, "allow")
	}
	code := redirected(e.t, resp, "https://client.example/cb").Get("code")
	st, tok := e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}, "tool", testSecret)
	if st != 200 || tok["refresh_token"] == nil {
		e.t.Fatalf("sign-in: %d %v", st, tok)
	}
	return tok
}

func (e *testEnv) refresh(rt any) (int, map[string]any) {
	e.t.Helper()
	s, _ := rt.(string)
	return e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s}}, "tool", testSecret)
}

func (e *testEnv) dropCache(id string) { e.rdb.Del(context.Background(), personKey+id) }

// 1. A failure of the instance during refresh keeps the refresh token.
func TestRefreshKeepsTokenOnUpstreamFailure(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	refused := e.auditCount("refused", "109")
	for _, c := range []struct {
		status int
		body   string
	}{{503, "down"}, {429, `{"error":"Too many requests"}`}, {404, "<html>not found</html>"}} {
		e.dropCache("109")
		e.f.admin(c.status, c.body)
		if st, out := e.refresh(tok["refresh_token"]); st != 503 || out["error"] != "temporarily_unavailable" {
			t.Fatalf("instance %d: %d %v", c.status, st, out)
		}
	}
	e.f.admin(0, "")
	if st, out := e.refresh(tok["refresh_token"]); st != 200 || out["refresh_token"] == nil {
		t.Fatalf("same refresh token after recovery: %d %v", st, out)
	}
	if e.auditCount("refused", "109") != refused {
		t.Fatal("a transient failure was logged as a refusal")
	}
}

// 1. Refresh uses a short cache, and concurrent lookups share one admin call.
func TestRefreshCacheAndSingleFlight(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	before := e.f.calls()
	st, tok2 := e.refresh(tok["refresh_token"])
	if st != 200 || e.f.calls() != before {
		t.Fatalf("refresh with a fresh cache asked the instance: %d, calls %d -> %d", st, before, e.f.calls())
	}
	e.rdb.Set(context.Background(), personKey+"109", `{"id":"109","cached_at":1}`, time.Minute) // stale
	if st, _ := e.refresh(tok2["refresh_token"]); st != 200 || e.f.calls() != before+1 {
		t.Fatalf("refresh with a stale cache: %d, calls %d", st, e.f.calls()-before)
	}

	e.f.mu.Lock()
	e.f.adminDelay = 200 * time.Millisecond
	e.f.mu.Unlock()
	before = e.f.calls()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Go(func() {
			if _, err := e.s.person(context.Background(), "109", 0); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := e.f.calls() - before; got != 1 {
		t.Fatalf("10 concurrent lookups made %d admin calls", got)
	}
}

// 1. Refreshes are rate limited per account.
func TestRefreshRateLimit(t *testing.T) {
	e := newTestEnv(t)
	rt := e.signIn(e.browser())["refresh_token"]
	for i := range refreshPerAccount {
		st, out := e.refresh(rt)
		if st != 200 {
			t.Fatalf("refresh %d: %d %v", i, st, out)
		}
		rt = out["refresh_token"]
	}
	req, _ := http.NewRequest("POST", e.app.URL+"/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt.(string)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("tool", testSecret)
	resp, err := e.app.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// The limited token is still good once the window passes.
	e.rdb.Del(context.Background(), rateKey+"acct:109:tool")
	if st, _ := e.refresh(rt); st != 200 {
		t.Fatalf("after the window: %d", st)
	}
}

// 1. A deleted account is cached as missing: userinfo doesn't hit the admin API each time.
func TestNegativeCache(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	e.f.mu.Lock()
	delete(e.f.accounts, "109")
	e.f.mu.Unlock()
	e.dropCache("109")
	before := e.f.calls()
	for range 3 {
		if st, _ := e.userinfo(tok["access_token"].(string)); st != 401 {
			t.Fatalf("userinfo of a deleted account: %d", st)
		}
	}
	if got := e.f.calls() - before; got != 1 {
		t.Fatalf("admin calls for a deleted account: %d", got)
	}
}

// 2. A rotated refresh token presented again revokes the whole family.
func TestRefreshReuseRevokesFamily(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	st, tok2 := e.refresh(tok["refresh_token"])
	if st != 200 {
		t.Fatalf("refresh: %d", st)
	}
	if st, _ := e.refresh(tok["refresh_token"]); st != 400 {
		t.Fatalf("reused refresh token: %d", st)
	}
	if st, _ := e.refresh(tok2["refresh_token"]); st != 400 {
		t.Fatalf("the newer refresh token survived a reuse: %d", st)
	}
	if st, _ := e.userinfo(tok2["access_token"].(string)); st != 401 {
		t.Fatalf("access token survived a reuse: %d", st)
	}
	// Another family of the same account is untouched.
	other := e.signIn(e.browser())
	if st, _ := e.refresh(other["refresh_token"]); st != 200 {
		t.Fatalf("other family: %d", st)
	}
}

// 2. A code redeemed twice revokes what it gave.
func TestCodeReplayRevokesFamily(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	verifier := randomToken()
	_, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid offline_access"))
	code := redirected(t, e.consent(b, page, "allow"), "https://client.example/cb").Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}
	st, tok := e.token(form, "tool", testSecret)
	if st != 200 {
		t.Fatalf("token: %d", st)
	}
	if st, _ := e.token(form, "tool", testSecret); st != 400 {
		t.Fatalf("replayed code: %d", st)
	}
	if st, _ := e.userinfo(tok["access_token"].(string)); st != 401 {
		t.Fatalf("access token survived a code replay: %d", st)
	}
	if st, _ := e.refresh(tok["refresh_token"]); st != 400 {
		t.Fatalf("refresh token survived a code replay: %d", st)
	}
}

// 2. Signing out here revokes the account's refresh tokens, but only when the
// person confirms on this site or the RP proves the session with an id_token_hint:
// a plain link from another site must not revoke anything.
func (e *testEnv) postLogout(b *http.Client, form url.Values, site string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.app.URL+"/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
	resp, err := b.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestLogoutRevokesRefreshTokens(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	tok := e.signIn(b)
	resp, page := e.get(b, "/logout", nil)
	if resp.StatusCode != 200 || !strings.Contains(page, `action="/logout"`) {
		t.Fatalf("logout without proof should ask to confirm: %d", resp.StatusCode)
	}
	if st, _ := e.userinfo(tok["access_token"].(string)); st != 200 {
		t.Fatalf("a plain GET revoked the tokens: %d", st)
	}
	m := hiddenRe.FindStringSubmatch(page)
	if m == nil || m[1] != "csrf" {
		t.Fatalf("no csrf in confirmation page:\n%s", page)
	}
	// A cross-site POST, or one without the right token, changes nothing.
	e.postLogout(b, url.Values{"csrf": {m[2]}}, "cross-site")
	e.postLogout(b, url.Values{"csrf": {"wrong"}}, "same-origin")
	if st, _ := e.userinfo(tok["access_token"].(string)); st != 200 {
		t.Fatalf("revoked without a valid confirmation: %d", st)
	}
	e.postLogout(b, url.Values{"csrf": {m[2]}}, "same-origin")
	if st, _ := e.refresh(tok["refresh_token"]); st != 400 {
		t.Fatalf("refresh after logout: %d", st)
	}
	if st, _ := e.userinfo(tok["access_token"].(string)); st != 401 {
		t.Fatalf("userinfo after logout: %d", st)
	}
}

func TestLogoutWithIDTokenHint(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	tok := e.signIn(b)
	if resp, page := e.get(b, "/logout", url.Values{"id_token_hint": {tok["id_token"].(string)}}); resp.StatusCode != 200 || strings.Contains(page, `action="/logout"`) {
		t.Fatalf("logout with hint: %d", resp.StatusCode)
	}
	if st, _ := e.refresh(tok["refresh_token"]); st != 400 {
		t.Fatalf("refresh after logout: %d", st)
	}
}

// 3. max_age without a session here forces a new sign-in on the instance.
func TestMaxAgeForcesLogin(t *testing.T) {
	e := newTestEnv(t)
	q := authParams("tool", "https://client.example/cb", "", "openid")
	q.Set("max_age", "300")
	e.get(e.browser(), "/authorize", q)
	if e.f.lastAuth.Get("force_login") != "true" {
		t.Fatalf("no force_login: %v", e.f.lastAuth)
	}
	e.get(e.browser(), "/authorize", authParams("tool", "https://client.example/cb", "", "openid"))
	if e.f.lastAuth.Get("force_login") != "" {
		t.Fatalf("force_login without max_age: %v", e.f.lastAuth)
	}
}

// 8. Logout only logs registered client ids; audit fields are cleaned.
func TestLogoutAuditClientID(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	e.signIn(b)
	_, page := e.get(b, "/logout", url.Values{"client_id": {strings.Repeat("x\n", 30000)}})
	if strings.Contains(page, "xx") {
		t.Fatal("unregistered client_id carried into the confirmation form")
	}
	m := hiddenRe.FindStringSubmatch(page)
	// 10000 × "x%0A" stays under the 64 KiB form limit, so the logout really runs.
	if resp := e.postLogout(b, url.Values{"csrf": {m[2]}, "client_id": {strings.Repeat("x\n", 10000)}}, "same-origin"); resp.StatusCode != 200 {
		t.Fatalf("confirmed logout: %d", resp.StatusCode)
	}
	var client string
	e.s.db.pool.QueryRow(context.Background(), `SELECT client_id FROM audit_log WHERE event = 'logout' ORDER BY id DESC LIMIT 1`).Scan(&client)
	if client != "" {
		t.Fatalf("unregistered client_id logged: %d bytes", len(client))
	}
}

// 9. "bearer" in any case.
func TestUserinfoBearerCase(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	for _, scheme := range []string{"bearer", "BEARER", "Bearer"} {
		req, _ := http.NewRequest("GET", e.app.URL+"/userinfo", nil)
		req.Header.Set("Authorization", scheme+" "+tok["access_token"].(string))
		resp, err := e.app.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", scheme, resp.StatusCode)
		}
	}
}

// 9. Only mapped roles become groups; raw role names never leave.
func TestRoleGroupsMapping(t *testing.T) {
	s := unitServer(t)
	s.cfg.roleGroups = map[string]string{"3": "admin"}
	p := person{ID: "1", RoleID: "2"}
	if c := s.claimsOf(p, []string{"openid", "profile", "groups"}); c.Groups != nil || c.Role != "" {
		t.Fatalf("unmapped role emitted: %+v", c)
	}
	p.RoleID = "3"
	if c := s.claimsOf(p, []string{"openid", "groups"}); len(c.Groups) != 1 || c.Groups[0] != "admin" || c.Role != "admin" {
		t.Fatalf("mapped role: %+v", c)
	}
	if c := s.claimsOf(p, []string{"openid", "email"}); c.Groups != nil {
		t.Fatalf("groups without the scope: %+v", c)
	}
	if _, err := parseRoleGroups(`{"3":"has space"}`); err == nil {
		t.Fatal("bad group name accepted")
	}
	if m, err := parseRoleGroups(`{"3":"admin","2":"moderator"}`); err != nil || m["2"] != "moderator" {
		t.Fatalf("parse: %v %v", m, err)
	}
}

// 7. Only Mastodon's JSON 404 means the account is gone.
func TestAdmin404(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	m := &mastodon{base: srv.URL, adminToken: "t", client: srv.Client()}
	for b, gone := range map[string]bool{`{"error":"Record not found"}`: true, "<html>404</html>": false, "": false, `{"x":1}`: false} {
		body = b
		_, err := m.adminAccount(context.Background(), "1")
		if errors.Is(err, errNoAccount) != gone || err == nil {
			t.Errorf("404 %q: %v", b, err)
		}
	}
}

// 6 and 9. Size caps, PKCE length, confidential clients need PKCE or nonce.
func TestAuthorizeHardening(t *testing.T) {
	s := unitServer(t)
	base := url.Values{"client_id": {"tool"}, "redirect_uri": {"https://client.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {"n"}}
	for name, set := range map[string]map[string]string{
		"long state":          {"state": strings.Repeat("s", 513)},
		"long nonce":          {"nonce": strings.Repeat("n", 256)},
		"44-char challenge":   {"code_challenge": strings.Repeat("a", 44), "code_challenge_method": "S256"},
		"neither pkce nonce":  {"nonce": ""},
		"challenge with dots": {"code_challenge": strings.Repeat("a", 42) + ".", "code_challenge_method": "S256"},
	} {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		for k, v := range set {
			if v == "" {
				q.Del(k)
			} else {
				q.Set(k, v)
			}
		}
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != 302 || loc.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// 9. http loopback redirect URIs only with "dev": true.
func TestLoopbackNeedsDev(t *testing.T) {
	cfg := `{"clients":[{"id":"a","name":"A","public":true,%s"redirect_uris":["http://localhost:3000/cb"]}]}`
	if _, err := parseClients([]byte(strings.Replace(cfg, "%s", "", 1)), nil); err == nil {
		t.Fatal("loopback accepted without dev")
	}
	if _, err := parseClients([]byte(strings.Replace(cfg, "%s", `"dev":true,`, 1)), nil); err != nil {
		t.Fatalf("dev client: %v", err)
	}
}

// 5, 9. Safer defaults; Redis needs a password.
func TestConfigDefaults(t *testing.T) {
	cur, _ := testPEMs(t)
	for k, v := range map[string]string{
		"ID_ISSUER": "https://id.example.social", "ID_INSTANCE": "https://example.social", "ID_MASTODON_CLIENT_ID": "a",
		"ID_MASTODON_CLIENT_SECRET": "b", "ID_MASTODON_ADMIN_TOKEN": "c", "ID_SIGNING_KEY": cur, "ID_CLIENTS_FILE": "x",
		"ID_DB_HOST": "db", "ID_DB_PASSWORD": "p", "ID_REDIS_ADDR": "r:6379", "ID_REDIS_PASSWORD": "",
		"ID_DB_SSLMODE": "", "ID_SESSION_TTL": "", "ID_ROLE_GROUPS": `{"3":"admin"}`,
	} {
		t.Setenv(k, v)
	}
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "ID_REDIS_PASSWORD") {
		t.Fatalf("no redis password: %v", err)
	}
	t.Setenv("ID_REDIS_PASSWORD", "pw")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.dbSSLMode != "require" || c.sessionTTL != 2*time.Hour || c.roleGroups["3"] != "admin" {
		t.Fatalf("defaults: sslmode %s, session %s, groups %v", c.dbSSLMode, c.sessionTTL, c.roleGroups)
	}
}

func TestAuditText(t *testing.T) {
	if got := auditText("a\x00b\nc‮"); got != "abc‮" && got != "abc" {
		t.Fatalf("control chars: %q", got)
	}
	if got := auditText(strings.Repeat("é", 1000)); len([]rune(got)) != maxAuditField {
		t.Fatalf("length: %d", len([]rune(got)))
	}
}

// A code issued before a sign-out can't be redeemed after it (Strix retest).
func TestCodeIssuedBeforeLogout(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	tok := e.signIn(b)
	verifier := randomToken()
	resp, page := e.get(b, "/authorize", authParams("tool", "https://client.example/cb", verifier, "openid profile offline_access"))
	if resp.StatusCode == 200 {
		resp = e.consent(b, page, "allow")
	}
	code := redirected(t, resp, "https://client.example/cb").Get("code")
	e.get(b, "/logout", url.Values{"id_token_hint": {tok["id_token"].(string)}})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}
	if st, _ := e.token(form, "tool", testSecret); st != 400 {
		t.Fatalf("code redeemed after logout: %d", st)
	}
}

// --- Strix retest ---------------------------------------------------------------

// signInOther is signIn for another registered client.
func (e *testEnv) signInOther(b *http.Client) map[string]any {
	e.t.Helper()
	resp, page := e.get(b, "/authorize", authParams("other", "https://other.example/cb", "", "openid offline_access"))
	if resp.StatusCode == 200 {
		resp = e.consent(b, page, "allow")
	}
	code := redirected(e.t, resp, "https://other.example/cb").Get("code")
	st, tok := e.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://other.example/cb"}}, "other", testSecret+"x")
	if st != 200 || tok["refresh_token"] == nil {
		e.t.Fatalf("sign-in to other: %d %v", st, tok)
	}
	return tok
}

// 1. One client looping on refresh doesn't lock the account out of other clients.
func TestRefreshLimitPerAccountAndClient(t *testing.T) {
	e := newTestEnv(t)
	b := e.browser()
	rt := e.signIn(b)["refresh_token"]
	other := e.signInOther(b)
	for range refreshPerAccount {
		st, out := e.refresh(rt)
		if st != 200 {
			t.Fatalf("refresh: %d", st)
		}
		rt = out["refresh_token"]
	}
	if st, _ := e.refresh(rt); st != 429 {
		t.Fatalf("tool over its limit: %d", st)
	}
	st, out := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {other["refresh_token"].(string)}}, "other", testSecret+"x")
	if st != 200 {
		t.Fatalf("other client locked out by tool's loop: %d %v", st, out)
	}
}

// 2. The limiter sets its own expiry (no EXPIRE NX), repairs a counter without
// one, and refuses when Redis fails.
func TestRateLimiter(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if ok, wait, err := e.s.allow(ctx, "t1", 2); !ok || err != nil || wait <= 0 || wait > time.Minute {
		t.Fatalf("first hit: %v %v %v", ok, wait, err)
	}
	if ttl := e.rdb.PTTL(ctx, rateKey+"t1").Val(); ttl <= 0 {
		t.Fatalf("no expiry: %v", ttl)
	}
	e.s.allow(ctx, "t1", 2)
	if ok, _, _ := e.s.allow(ctx, "t1", 2); ok {
		t.Fatal("third hit allowed with limit 2")
	}
	e.rdb.Set(ctx, rateKey+"t2", 5, 0) // a counter that lost its expiry
	e.s.allow(ctx, "t2", 100)
	if ttl := e.rdb.PTTL(ctx, rateKey+"t2").Val(); ttl <= 0 {
		t.Fatalf("expiry not repaired: %v", ttl)
	}
	broken := *e.s
	broken.rdb = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	if ok, _, err := broken.allow(ctx, "t3", 100); ok || err == nil {
		t.Fatalf("limiter failed open: %v %v", ok, err)
	}
}

// 3. A failure while storing the successor tokens leaves the old refresh token
// usable and marks nothing as used.
func TestRotationFailureKeepsToken(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	tok := e.signIn(e.browser())
	rt := tok["refresh_token"].(string)
	var g grant
	if err := e.s.kv.get(ctx, refreshKey+hashID(rt), &g); err != nil {
		t.Fatal(err)
	}
	// Make tracking the new tokens fail (wrong Redis type for the family set).
	e.rdb.Del(ctx, familyKeys+g.Family)
	e.rdb.Set(ctx, familyKeys+g.Family, "x", time.Minute)
	if st, _ := e.refresh(rt); st != 503 {
		t.Fatalf("refresh with a storage failure: %d", st)
	}
	if n := e.rdb.Exists(ctx, refreshUsed+hashID(rt)).Val(); n != 0 {
		t.Fatal("old token marked used without a successor")
	}
	e.rdb.Del(ctx, familyKeys+g.Family)
	st, out := e.refresh(rt)
	if st != 200 {
		t.Fatalf("retry after the failure: %d %v", st, out)
	}
	if st, _ := e.userinfo(out["access_token"].(string)); st != 200 {
		t.Fatalf("family revoked by the retry: %d", st)
	}
}

// 4. RP-initiated logout with a valid id_token_hint and no session here still
// revokes the account's tokens; a forged hint revokes nothing.
func TestLogoutHintWithoutSession(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(e.browser())
	hint := tok["id_token"].(string)
	parts := strings.Split(hint, ".")
	forged := parts[0] + "." + b64([]byte(`{"iss":"`+e.app.URL+`","sub":"109","aud":"tool"}`)) + "." + parts[2]
	e.get(e.browser(), "/logout", url.Values{"id_token_hint": {forged}})
	if st, _ := e.refresh(tok["refresh_token"]); st != 200 {
		t.Fatalf("forged hint revoked tokens: %d", st)
	}
	tok = e.signIn(e.browser())
	e.get(e.browser(), "/logout", url.Values{"id_token_hint": {tok["id_token"].(string)}})
	if st, _ := e.refresh(tok["refresh_token"]); st != 400 {
		t.Fatalf("refresh after hint logout: %d", st)
	}
	if st, _ := e.userinfo(tok["access_token"].(string)); st != 401 {
		t.Fatalf("userinfo after hint logout: %d", st)
	}
}
