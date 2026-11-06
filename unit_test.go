package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.gutocarvalho.net/open/bolha/id/internal/relnotes"
)

var (
	keyOnce  sync.Once
	testKeys [2]string
)

// testPEMs returns two RSA keys in PEM, generated once per test run.
func testPEMs(t *testing.T) (string, string) {
	t.Helper()
	keyOnce.Do(func() {
		for i := range testKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			der, _ := x509.MarshalPKCS8PrivateKey(k)
			testKeys[i] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		}
	})
	return testKeys[0], testKeys[1]
}

func testKeySet(t *testing.T) *keySet {
	cur, prev := testPEMs(t)
	ks, err := newKeySet(cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// Every VERSION needs its CHANGELOG.md entry: the release notes page is built from it.
func TestChangelogHasVersion(t *testing.T) {
	if err := relnotes.Check(changelog, versionFile); err != nil {
		t.Fatal(err)
	}
}

func TestTranslationsHaveSameKeys(t *testing.T) {
	en, pt := translations["en"], translations["pt-BR"]
	for k := range en {
		if _, ok := pt[k]; !ok {
			t.Errorf("pt-BR misses %q", k)
		}
	}
	for k := range pt {
		if _, ok := en[k]; !ok {
			t.Errorf("en misses %q", k)
		}
	}
}

// unitServer has no Redis or database: enough for pages and early errors.
func unitServer(t *testing.T) *server {
	t.Helper()
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	clients, err := parseClients([]byte(testClientsJSON), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{issuer: "https://id.example.social", instance: "https://example.social", domain: "example.social", lang: "en", allowSilenced: true}
	return newServer(cfg, tmpl, nil, nil, nil, testKeySet(t), clients)
}

func TestReleaseNotesPage(t *testing.T) {
	s := unitServer(t)
	for path, want := range map[string]string{"/release-notes": `id="v` + releases[0].Version + `"`, "/release-notes.json": `"app": "id"`} {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: %d, missing %q", path, rec.Code, want)
		}
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	s := unitServer(t)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	var d map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d["issuer"] != "https://id.example.social" || d["token_endpoint"] != "https://id.example.social/token" || d["jwks_uri"] != "https://id.example.social/jwks.json" {
		t.Fatalf("discovery: %v", d)
	}
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/jwks.json", nil))
	var set struct{ Keys []jwk }
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil || len(set.Keys) != 2 {
		t.Fatalf("jwks: %v %s", err, rec.Body)
	}
	if set.Keys[0].Kid == set.Keys[1].Kid || set.Keys[0].Kid != s.keys.kid {
		t.Fatalf("kids: %+v", set.Keys)
	}
}

func TestSignVerifyAndRotation(t *testing.T) {
	cur, prev := testPEMs(t)
	old, err := newKeySet(prev, "")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := old.sign(idClaims{Iss: "x", Sub: "1", Aud: "c", Exp: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := newKeySet(cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	var c idClaims
	if err := rotated.verify(tok, &c); err != nil || c.Sub != "1" {
		t.Fatalf("token of the previous key: %v %+v", err, c)
	}
	// After the previous key is dropped, its tokens don't verify.
	alone, _ := newKeySet(cur, "")
	if err := alone.verify(tok, &c); err == nil {
		t.Fatal("token of a dropped key verified")
	}
	// A tampered payload fails.
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + b64([]byte(`{"iss":"x","sub":"2"}`)) + "." + parts[2]
	if err := rotated.verify(forged, &c); err == nil {
		t.Fatal("forged token verified")
	}
	// alg none is refused.
	none := b64([]byte(`{"alg":"none","kid":"`+rotated.kid+`"}`)) + "." + parts[1] + "."
	if err := rotated.verify(none, &c); err == nil {
		t.Fatal("alg none verified")
	}
}

func TestSmallKeyRefused(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if _, err := newKeySet(string(p), ""); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

const testSecret = "s3cret-s3cret-s3cret-s3cret-s3cret-0123"

var testClientsJSON = `{"clients": [
  {"id": "tool", "name": "Tool", "secret_sha256": "` + sha256hex(testSecret) + `",
   "redirect_uris": ["https://client.example/cb"], "post_logout_redirect_uris": ["https://client.example/bye"]},
  {"id": "other", "name": "Other", "secret_sha256": "` + sha256hex(testSecret+"x") + `", "redirect_uris": ["https://other.example/cb"]},
  {"id": "spa", "name": "SPA", "public": true, "redirect_uris": ["https://spa.example/cb", "http://localhost:3000/cb"]}
]}`

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestParseClients(t *testing.T) {
	getenv := func(k string) string {
		if k == "LONG" {
			return strings.Repeat("a", 40)
		}
		return "short"
	}
	good := `{"clients":[{"id":"a","name":"A","secret_env":"LONG","redirect_uris":["https://a.example/cb"]}]}`
	cs, err := parseClients([]byte(good), getenv)
	if err != nil || !cs["a"].checkSecret(strings.Repeat("a", 40)) || cs["a"].checkSecret("nope") {
		t.Fatalf("good config: %v", err)
	}
	bad := map[string]string{
		"short env secret": `{"clients":[{"id":"a","name":"A","secret_env":"SHORT","redirect_uris":["https://a.example/cb"]}]}`,
		"no secret":        `{"clients":[{"id":"a","name":"A","redirect_uris":["https://a.example/cb"]}]}`,
		"public w/ secret": `{"clients":[{"id":"a","name":"A","public":true,"secret_env":"LONG","redirect_uris":["https://a.example/cb"]}]}`,
		"http redirect":    `{"clients":[{"id":"a","name":"A","public":true,"redirect_uris":["http://a.example/cb"]}]}`,
		"fragment":         `{"clients":[{"id":"a","name":"A","public":true,"redirect_uris":["https://a.example/cb#x"]}]}`,
		"relative":         `{"clients":[{"id":"a","name":"A","public":true,"redirect_uris":["/cb"]}]}`,
		"duplicate":        `{"clients":[{"id":"a","name":"A","public":true,"redirect_uris":["https://a.example/cb"]},{"id":"a","name":"B","public":true,"redirect_uris":["https://b.example/cb"]}]}`,
		"unknown field":    `{"clients":[{"id":"a","name":"A","public":true,"secret":"x","redirect_uris":["https://a.example/cb"]}]}`,
		"bad hash":         `{"clients":[{"id":"a","name":"A","secret_sha256":"abc","redirect_uris":["https://a.example/cb"]}]}`,
	}
	for name, cfg := range bad {
		if _, err := parseClients([]byte(cfg), getenv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An unknown client or an unregistered redirect URI shows a page and never redirects.
func TestAuthorizeNeverRedirectsToUnregisteredURI(t *testing.T) {
	s := unitServer(t)
	for name, q := range map[string]url.Values{
		"unknown client":   {"client_id": {"nope"}, "redirect_uri": {"https://client.example/cb"}, "response_type": {"code"}, "scope": {"openid"}},
		"wrong redirect":   {"client_id": {"tool"}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"}, "scope": {"openid"}},
		"prefix redirect":  {"client_id": {"tool"}, "redirect_uri": {"https://client.example/cb/x"}, "response_type": {"code"}, "scope": {"openid"}},
		"other's redirect": {"client_id": {"tool"}, "redirect_uri": {"https://other.example/cb"}, "response_type": {"code"}, "scope": {"openid"}},
		"query added":      {"client_id": {"tool"}, "redirect_uri": {"https://client.example/cb?a=1"}, "response_type": {"code"}, "scope": {"openid"}},
		"no redirect":      {"client_id": {"tool"}, "response_type": {"code"}, "scope": {"openid"}},
	} {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil))
		if rec.Code != 400 || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %d, Location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// Once the redirect URI is good, errors go back to the client with the state.
func TestAuthorizeErrorsRedirect(t *testing.T) {
	s := unitServer(t)
	base := url.Values{"client_id": {"tool"}, "redirect_uri": {"https://client.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"st"}}
	cases := map[string]struct {
		set  map[string]string
		want string
	}{
		"no openid":      {map[string]string{"scope": "profile email"}, "invalid_scope"},
		"token response": {map[string]string{"response_type": "token"}, "unsupported_response_type"},
		"plain pkce":     {map[string]string{"code_challenge": strings.Repeat("a", 43), "code_challenge_method": "plain"}, "invalid_request"},
		"public no pkce": {map[string]string{"client_id": "spa", "redirect_uri": "https://spa.example/cb"}, "invalid_request"},
		"request object": {map[string]string{"request": "eyJ"}, "request_not_supported"},
		"bad prompt":     {map[string]string{"prompt": "none login"}, "invalid_request"},
	}
	for name, c := range cases {
		q := url.Values{}
		for k, v := range base {
			q[k] = slices.Clone(v)
		}
		for k, v := range c.set {
			q.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != 302 || loc == nil || loc.Query().Get("error") != c.want || loc.Query().Get("state") != "st" ||
			loc.Query().Get("iss") != "https://id.example.social" || !strings.HasPrefix(loc.String(), q.Get("redirect_uri")+"?") {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestRefusal(t *testing.T) {
	ok := person{ID: "1", Local: true, Approved: true, Confirmed: true, Email: "a@b"}
	if r := ok.refusal(true); r != "" {
		t.Fatalf("active account refused: %s", r)
	}
	for name, mut := range map[string]func(*person){
		"suspended":   func(p *person) { p.Suspended = true },
		"disabled":    func(p *person) { p.Disabled = true },
		"unapproved":  func(p *person) { p.Approved = false },
		"unconfirmed": func(p *person) { p.Confirmed = false },
		"remote":      func(p *person) { p.Local = false },
	} {
		p := ok
		mut(&p)
		if p.refusal(true) == "" {
			t.Errorf("%s accepted", name)
		}
	}
	silenced := ok
	silenced.Silenced = true
	if silenced.refusal(true) != "" || silenced.refusal(false) != "silenced" {
		t.Error("silenced handling")
	}
}
