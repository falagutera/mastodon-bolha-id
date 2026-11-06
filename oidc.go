package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	supportedScopes = []string{"openid", "profile", "email", "groups", "offline_access"}
	pkcePattern     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`) // verifier
	challengeRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)       // S256: 32 bytes, base64url
	singleParams    = []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "ui_locales"}
	claimsSupported = []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "preferred_username", "name", "picture", "profile", "email", "email_verified", "groups", "role"}
)

const (
	maxStateLen = 512
	maxNonceLen = 255
)

func (s *server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/authorize",
		"token_endpoint":                                 iss + "/token",
		"userinfo_endpoint":                              iss + "/userinfo",
		"jwks_uri":                                       iss + "/jwks.json",
		"end_session_endpoint":                           iss + "/logout",
		"scopes_supported":                               supportedScopes,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               claimsSupported,
		"prompt_values_supported":                        []string{"none", "login", "consent"},
		"ui_locales_supported":                           []string{"pt-BR", "en"},
		"claims_parameter_supported":                     false,
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Clients cache it; a rotation keeps the previous key published for a while.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(s.keys.jwks())
}

// parseScopes keeps the scopes this provider knows, once each, in a stable order.
// Unknown scopes are ignored, as OpenID Connect asks.
func parseScopes(raw string) []string {
	have := strings.Fields(raw)
	var out []string
	for _, sc := range supportedScopes {
		if slices.Contains(have, sc) {
			out = append(out, sc)
		}
	}
	return out
}

func hasPrompt(prompt, value string) bool { return slices.Contains(strings.Fields(prompt), value) }

// redirectTo sends the browser to a registered redirect URI with extra
// parameters, keeping the URI's own query.
func (s *server) redirectTo(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values, status int) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "bad_redirect")
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	q.Set("iss", s.cfg.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), status)
}

func (s *server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string, status int) {
	p := url.Values{"error": {code}}
	if description != "" {
		p.Set("error_description", description)
	}
	if state != "" {
		p.Set("state", state)
	}
	s.redirectTo(w, r, redirectURI, p, status)
}

// handleAuthorize validates the request. Until the client and the redirect URI
// are known to be good, errors show a page and never redirect.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lang := uiLocale(q.Get("ui_locales"))
	c := s.clients[q.Get("client_id")]
	if c == nil || len(q["client_id"]) != 1 {
		s.renderErrorLang(w, r, http.StatusBadRequest, "bad_client", lang)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if len(q["redirect_uri"]) != 1 || !c.allowsRedirect(redirectURI) {
		s.renderErrorLang(w, r, http.StatusBadRequest, "bad_redirect", lang)
		return
	}
	state := q.Get("state")
	fail := func(code, description string) {
		s.redirectError(w, r, redirectURI, state, code, description, http.StatusFound)
	}
	for _, p := range singleParams {
		if len(q[p]) > 1 {
			fail("invalid_request", p+" is repeated")
			return
		}
	}
	req := authRequest{ClientID: c.ID, RedirectURI: redirectURI, State: state, Nonce: q.Get("nonce"), Prompt: q.Get("prompt"), Lang: lang}
	switch {
	case q.Get("request") != "":
		fail("request_not_supported", "")
		return
	case q.Get("request_uri") != "":
		fail("request_uri_not_supported", "")
		return
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only code is supported")
		return
	case len(state) > maxStateLen || len(req.Nonce) > maxNonceLen:
		fail("invalid_request", "state or nonce too long")
		return
	}
	req.Scopes = parseScopes(q.Get("scope"))
	if !slices.Contains(req.Scopes, "openid") {
		fail("invalid_scope", "openid is required")
		return
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	switch {
	case challenge == "" && c.Public:
		fail("invalid_request", "PKCE (S256) is required")
		return
	case challenge == "" && req.Nonce == "":
		// A confidential client must bind the code to its own session somehow.
		fail("invalid_request", "PKCE or nonce is required")
		return
	case challenge == "" && method != "":
		fail("invalid_request", "code_challenge is missing")
		return
	case challenge != "" && method != "S256":
		fail("invalid_request", "code_challenge_method must be S256")
		return
	case challenge != "" && !challengeRe.MatchString(challenge):
		fail("invalid_request", "malformed code_challenge")
		return
	}
	req.Challenge = challenge
	for _, p := range strings.Fields(req.Prompt) {
		if !slices.Contains([]string{"none", "login", "consent", "select_account"}, p) {
			fail("invalid_request", "unknown prompt value")
			return
		}
	}
	if hasPrompt(req.Prompt, "none") && len(strings.Fields(req.Prompt)) > 1 {
		fail("invalid_request", "prompt=none can't be combined")
		return
	}
	maxAge := -1
	if v := q.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			fail("invalid_request", "malformed max_age")
			return
		}
		maxAge = n
	}

	sess, ok, err := s.currentSession(r)
	if err != nil {
		log.Printf("session: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", lang)
		return
	}
	fresh := ok && (maxAge < 0 || s.now().Unix()-sess.AuthTime <= int64(maxAge))
	needLogin := !fresh || hasPrompt(req.Prompt, "login") || hasPrompt(req.Prompt, "select_account")
	if needLogin && hasPrompt(req.Prompt, "none") {
		fail("login_required", "")
		return
	}
	requestID, err := s.kv.newSecret(r.Context(), requestKey, req, requestTTL)
	if err != nil {
		log.Printf("authorize: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", lang)
		return
	}
	if needLogin {
		// A new sign-in on the instance too, when asked for or when the session here is too old.
		force := ok || maxAge >= 0 || hasPrompt(req.Prompt, "login") || hasPrompt(req.Prompt, "select_account")
		s.startLogin(w, r, requestID, force, lang)
		return
	}
	s.continueAuth(w, r, sess, requestID, req)
}

// continueAuth runs once the person is signed in here: account status, then
// consent, then the code.
func (s *server) continueAuth(w http.ResponseWriter, r *http.Request, sess session, requestID string, req authRequest) {
	ctx := r.Context()
	c := s.clients[req.ClientID]
	if c == nil { // removed from the config meanwhile
		s.renderErrorLang(w, r, http.StatusBadRequest, "bad_client", req.Lang)
		return
	}
	p, err := s.person(ctx, sess.AccountID, personTTL)
	if err != nil && !errors.Is(err, errNoAccount) {
		log.Printf("admin account %s: %v", sess.AccountID, err)
		s.renderErrorLang(w, r, http.StatusBadGateway, "instance", req.Lang)
		return
	}
	reason := "gone"
	if err == nil {
		reason = p.refusal(s.cfg.allowSilenced)
	}
	if reason != "" {
		s.endSession(w, r, sess)
		s.kv.del(ctx, requestKey+hashID(requestID))
		s.auditLog(ctx, auditEntry{AccountID: sess.AccountID, Acct: p.Username, ClientID: c.ID, Event: "refused", Detail: reason})
		if hasPrompt(req.Prompt, "none") {
			s.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "", http.StatusFound)
			return
		}
		s.renderErrorLang(w, r, http.StatusForbidden, refusalKey(reason), req.Lang)
		return
	}
	done := false
	if !hasPrompt(req.Prompt, "consent") {
		done, err = s.db.consented(ctx, p.ID, c.ID, req.Scopes)
		if err != nil {
			log.Printf("consent: %v", err)
			s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", req.Lang)
			return
		}
	}
	if done {
		s.kv.del(ctx, requestKey+hashID(requestID))
		s.issueCode(w, r, req, sess, p, http.StatusFound)
		return
	}
	if hasPrompt(req.Prompt, "none") {
		s.kv.del(ctx, requestKey+hashID(requestID))
		s.redirectError(w, r, req.RedirectURI, req.State, "consent_required", "", http.StatusFound)
		return
	}
	// The consent form only works for the account that saw it.
	req.AccountID = sess.AccountID
	if err := s.kv.put(ctx, requestKey+hashID(requestID), req, requestTTL); err != nil {
		log.Printf("consent: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", req.Lang)
		return
	}
	v := s.view(r, req.Lang)
	v.ClientName, v.Acct, v.RequestID, v.CSRF = c.Name, p.Username, requestID, sess.CSRF
	v.Shares = shares(v.T, req.Scopes)
	w.Header().Set("Content-Security-Policy", csp("'self' "+origin(req.RedirectURI)))
	s.render(w, "consent.html", http.StatusOK, v)
}

func shares(t map[string]string, scopes []string) []string {
	out := []string{t["share_id"]}
	if slices.Contains(scopes, "profile") {
		out = append(out, t["share_profile"])
	}
	if slices.Contains(scopes, "email") {
		out = append(out, t["share_email"])
	}
	if slices.Contains(scopes, "profile") || slices.Contains(scopes, "groups") {
		out = append(out, t["share_role"])
	}
	if slices.Contains(scopes, "offline_access") {
		out = append(out, t["share_offline"])
	}
	return out
}

func refusalKey(reason string) string {
	switch reason {
	case "unapproved", "unconfirmed", "no_email":
		return "refused_pending"
	}
	return "refused"
}

func (s *server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if !sameSite(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sess, ok, err := s.currentSession(r)
	if err != nil {
		log.Printf("session: %v", err)
		s.renderError(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if !ok {
		s.renderError(w, r, http.StatusForbidden, "expired")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil || !equal(sess.CSRF, r.PostFormValue("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "expired")
		return
	}
	ctx := r.Context()
	var req authRequest
	err = s.kv.take(ctx, requestKey+hashID(r.PostFormValue("request")), &req)
	if errors.Is(err, errMissing) || (err == nil && req.AccountID != sess.AccountID) {
		s.renderError(w, r, http.StatusBadRequest, "expired")
		return
	}
	if err != nil {
		log.Printf("consent: %v", err)
		s.renderError(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	c := s.clients[req.ClientID]
	if c == nil || !c.allowsRedirect(req.RedirectURI) {
		s.renderErrorLang(w, r, http.StatusBadRequest, "bad_client", req.Lang)
		return
	}
	p, err := s.person(ctx, sess.AccountID, personTTL)
	if err != nil && !errors.Is(err, errNoAccount) {
		log.Printf("admin account %s: %v", sess.AccountID, err)
		s.renderErrorLang(w, r, http.StatusBadGateway, "instance", req.Lang)
		return
	}
	if err != nil || p.refusal(s.cfg.allowSilenced) != "" {
		s.renderErrorLang(w, r, http.StatusForbidden, "refused", req.Lang)
		return
	}
	if r.PostFormValue("decision") != "allow" {
		s.auditLog(ctx, auditEntry{AccountID: p.ID, Acct: p.Username, ClientID: c.ID, Event: "deny"})
		s.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "", http.StatusSeeOther)
		return
	}
	if err := s.db.consent(ctx, p.ID, c.ID, req.Scopes); err != nil {
		log.Printf("consent: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", req.Lang)
		return
	}
	s.auditLog(ctx, auditEntry{AccountID: p.ID, Acct: p.Username, ClientID: c.ID, Event: "consent", Detail: strings.Join(req.Scopes, " ")})
	s.issueCode(w, r, req, sess, p, http.StatusSeeOther)
}

func (s *server) issueCode(w http.ResponseWriter, r *http.Request, req authRequest, sess session, p person, status int) {
	g := grant{ClientID: req.ClientID, AccountID: p.ID, Scopes: req.Scopes, AuthTime: sess.AuthTime,
		RedirectURI: req.RedirectURI, Challenge: req.Challenge, Nonce: req.Nonce, Family: randomToken()}
	// The family joins the account before the code exists, so a sign-out between
	// issuing and redeeming the code revokes it too.
	err := s.registerFamily(r.Context(), g.Family, p.ID)
	var code string
	if err == nil {
		code, err = s.kv.newSecret(r.Context(), codeKey, g, codeTTL)
	}
	if err != nil {
		log.Printf("code: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", req.Lang)
		return
	}
	s.auditLog(r.Context(), auditEntry{AccountID: p.ID, Acct: p.Username, ClientID: req.ClientID, Event: "login"})
	params := url.Values{"code": {code}}
	if req.State != "" {
		params.Set("state", req.State)
	}
	s.redirectTo(w, r, req.RedirectURI, params, status)
}
