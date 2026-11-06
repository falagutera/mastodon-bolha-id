package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.gutocarvalho.net/open/bolha/id/internal/relnotes"
)

const (
	sessionCookie = "__Host-id"
	stateCookie   = "__Host-id-state"
	maxFormBody   = 64 << 10
)

type server struct {
	cfg     config
	tmpl    *template.Template
	api     *mastodon
	db      *store
	rdb     *redis.Client
	kv      kv
	keys    *keySet
	clients clientList
	now     func() time.Time
}

func newServer(cfg config, tmpl *template.Template, api *mastodon, db *store, rdb *redis.Client, keys *keySet, clients clientList) *server {
	return &server{cfg: cfg, tmpl: tmpl, api: api, db: db, rdb: rdb, kv: kv{rdb: rdb}, keys: keys, clients: clients, now: time.Now}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
	})
	assets, err := fs.Sub(assetFS, "assets")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(assets)))
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /release-notes", s.handleNotes)
	mux.Handle("GET /release-notes.json", relnotes.JSONHandler("id", version, releases))

	// OpenID Connect. The machine endpoints allow any origin: they use no cookies.
	mux.Handle("GET /.well-known/openid-configuration", cors(http.HandlerFunc(s.handleDiscovery)))
	mux.Handle("GET /jwks.json", cors(http.HandlerFunc(s.handleJWKS)))
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("POST /consent", s.handleConsent)
	mux.Handle("POST /token", cors(http.HandlerFunc(s.handleToken)))
	mux.Handle("GET /userinfo", cors(http.HandlerFunc(s.handleUserinfo)))
	mux.Handle("POST /userinfo", cors(http.HandlerFunc(s.handleUserinfo)))
	mux.Handle("OPTIONS /token", cors(http.HandlerFunc(noContent)))
	mux.Handle("OPTIONS /userinfo", cors(http.HandlerFunc(noContent)))
	mux.HandleFunc("GET /logout", s.handleLogout)
	mux.HandleFunc("POST /logout", s.handleLogout)
	return securityHeaders(mux)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		http.Error(w, "redis", http.StatusServiceUnavailable)
		return
	}
	if err := s.db.pool.Ping(ctx); err != nil {
		http.Error(w, "database", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

func noContent(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		next.ServeHTTP(w, r)
	})
}

// csp is the page policy. Only form-action varies: the consent form ends at the
// client's redirect URI, and browsers check form-action across redirects.
func csp(formAction string) string {
	return "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; base-uri 'none'; form-action " +
		formAction + "; frame-ancestors 'none'"
}

// securityHeaders allows same-origin scripts for the bar the edge injects on
// bolha sites. Nothing inline runs.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp("'self'"))
		next.ServeHTTP(w, r)
	})
}

// sameSite rejects requests started by another site, before reading any body.
func sameSite(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

func (s *server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		// Lax: the cookie must survive the top-level redirects from the tools and the instance.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) clearCookie(w http.ResponseWriter, name string) {
	s.setCookie(w, name, "", -time.Second)
}

// currentSession reads the session cookie. A Redis failure is an error, a
// missing or expired session is not.
func (s *server) currentSession(r *http.Request) (session, bool, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return session{}, false, nil
	}
	var sess session
	err = s.kv.get(r.Context(), sessionKey+hashID(c.Value), &sess)
	if errors.Is(err, errMissing) {
		return session{}, false, nil
	}
	if err != nil {
		return session{}, false, err
	}
	sess.ID = c.Value
	return sess, true, nil
}

func (s *server) endSession(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.ID != "" {
		if err := s.kv.del(r.Context(), sessionKey+hashID(sess.ID)); err != nil {
			log.Printf("end session: %v", err)
		}
	}
	s.clearCookie(w, sessionCookie)
}

func (s *server) auditLog(ctx context.Context, e auditEntry) {
	if err := s.db.audit(ctx, e); err != nil {
		log.Printf("audit %s %s %s: %v", e.Event, e.AccountID, e.ClientID, err)
	}
}

type viewData struct {
	Version  string
	T        map[string]string
	Lang     string
	Domain   string
	Issuer   string
	Nav      string
	Message  string
	Acct     string
	Clients  []string
	Releases template.HTML
	// Consent page.
	ClientName string
	Shares     []string
	RequestID  string
	CSRF       string
	// Logout confirmation page.
	ClientID     string
	LogoutTarget string
	State        string
	UILocales    string
}

func (s *server) view(r *http.Request, lang string) viewData {
	if lang == "" {
		lang = language(r, s.cfg.lang)
	}
	return viewData{T: strs(lang), Lang: lang, Version: version, Domain: s.cfg.domain, Issuer: s.cfg.issuer}
}

func (s *server) render(w http.ResponseWriter, name string, status int, v viewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, v); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func (s *server) renderError(w http.ResponseWriter, r *http.Request, status int, key string) {
	s.renderErrorLang(w, r, status, key, "")
}

func (s *server) renderErrorLang(w http.ResponseWriter, r *http.Request, status int, key, lang string) {
	v := s.view(r, lang)
	v.Message = v.T["error_"+key]
	s.render(w, "error.html", status, v)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query().Get("lang"); q != "" {
		setLanguage(w, q)
	}
	v := s.view(r, "")
	sess, ok, err := s.currentSession(r)
	if err != nil {
		log.Printf("session: %v", err)
	}
	if ok {
		if p, err := s.person(r.Context(), sess.AccountID, personTTL); err == nil {
			v.Acct = p.Username
		}
	}
	for _, c := range s.clients {
		v.Clients = append(v.Clients, c.Name)
	}
	slices.Sort(v.Clients)
	s.render(w, "index.html", http.StatusOK, v)
}

func (s *server) handleNotes(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query().Get("lang"); q != "" {
		setLanguage(w, q)
	}
	v := s.view(r, "")
	v.Nav = "notes"
	v.Releases = relnotes.HTML(releases)
	s.render(w, "notes.html", http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json: %v", err)
	}
}
