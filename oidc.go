package main

import (
	"context"
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
	pkcePattern     = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	singleParams    = []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "ui_locales"}
	claimsSupported = []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username", "name", "picture", "profile", "email", "email_verified", "groups", "role"}
)

const (
	maxStateLen = 2048
	maxNonceLen = 512
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
	case challenge == "" && method != "":
		fail("invalid_request", "code_challenge is missing")
		return
	case challenge != "" && method != "S256":
		fail("invalid_request", "code_challenge_method must be S256")
		return
	case challenge != "" && !pkcePattern.MatchString(challenge):
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
		force := ok || hasPrompt(req.Prompt, "login") || hasPrompt(req.Prompt, "select_account")
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
	p, err := s.person(ctx, sess.AccountID, false)
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
	p, err := s.person(ctx, sess.AccountID, false)
	if err == nil && p.refusal(s.cfg.allowSilenced) != "" {
		err = errNoAccount
	}
	if err != nil {
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
		RedirectURI: req.RedirectURI, Challenge: req.Challenge, Nonce: req.Nonce}
	code, err := s.kv.newSecret(r.Context(), codeKey, g, codeTTL)
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

// person returns the account status and claims, from a cache of up to
// personTTL unless fresh is set.
func (s *server) person(ctx context.Context, id string, fresh bool) (person, error) {
	var p person
	if !fresh {
		err := s.kv.get(ctx, personKey+id, &p)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, errMissing) {
			log.Printf("person cache: %v", err)
		}
	}
	a, err := s.api.adminAccount(ctx, id)
	if err != nil {
		return p, err
	}
	p = personOf(a)
	if err := s.kv.put(ctx, personKey+id, p, personTTL); err != nil {
		log.Printf("person cache: %v", err)
	}
	return p, nil
}

// --- token endpoint ---------------------------------------------------------

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func tokenFail(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="id"`)
	}
	writeJSON(w, status, tokenError{code, description})
}

// authenticateClient accepts client_secret_basic, client_secret_post, and none
// for public clients. Only one method per request.
func (s *server) authenticateClient(r *http.Request) (*client, bool) {
	id, secret, basic := r.BasicAuth()
	formID, formSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if basic {
		// RFC 6749 2.3.1: both are form-encoded inside the header.
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil || formSecret != "" || (formID != "" && formID != id) {
			return nil, false
		}
	} else {
		id, secret = formID, formSecret
	}
	c := s.clients[id]
	if c == nil {
		return nil, false
	}
	if c.Public {
		return c, secret == "" && !basic
	}
	return c, c.checkSecret(secret)
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			tokenFail(w, http.StatusBadRequest, "invalid_request", k+" is repeated")
			return
		}
	}
	c, ok := s.authenticateClient(r)
	if !ok {
		tokenFail(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	ctx := r.Context()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		var g grant
		err := s.kv.take(ctx, codeKey+hashID(r.PostForm.Get("code")), &g)
		if errors.Is(err, errMissing) {
			tokenFail(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
			return
		}
		if err != nil {
			log.Printf("token: %v", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		if g.ClientID != c.ID || r.PostForm.Get("redirect_uri") != g.RedirectURI {
			tokenFail(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client or redirect_uri")
			return
		}
		verifier := r.PostForm.Get("code_verifier")
		if g.Challenge != "" && (!pkcePattern.MatchString(verifier) || !equal(s256(verifier), g.Challenge)) ||
			g.Challenge == "" && verifier != "" {
			tokenFail(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		s.issueTokens(w, r, c, g, false)
	case "refresh_token":
		var g grant
		err := s.kv.take(ctx, refreshKey+hashID(r.PostForm.Get("refresh_token")), &g)
		if errors.Is(err, errMissing) {
			tokenFail(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired refresh token")
			return
		}
		if err != nil {
			log.Printf("token: %v", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
		if g.ClientID != c.ID {
			tokenFail(w, http.StatusBadRequest, "invalid_grant", "")
			return
		}
		if sc := r.PostForm.Get("scope"); sc != "" {
			narrow := parseScopes(sc)
			for _, x := range narrow {
				if !slices.Contains(g.Scopes, x) {
					tokenFail(w, http.StatusBadRequest, "invalid_scope", "")
					return
				}
			}
			g.Scopes = narrow
		}
		g.Nonce = ""
		s.issueTokens(w, r, c, g, true)
	default:
		tokenFail(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// issueTokens checks the account again (from the instance itself on refresh,
// so a suspension ends access) and returns the tokens.
func (s *server) issueTokens(w http.ResponseWriter, r *http.Request, c *client, g grant, refresh bool) {
	ctx := r.Context()
	p, err := s.person(ctx, g.AccountID, refresh)
	if err != nil && !errors.Is(err, errNoAccount) {
		log.Printf("admin account %s: %v", g.AccountID, err)
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return
	}
	reason := "gone"
	if err == nil {
		reason = p.refusal(s.cfg.allowSilenced)
	}
	if reason != "" {
		s.auditLog(ctx, auditEntry{AccountID: g.AccountID, Acct: p.Username, ClientID: c.ID, Event: "refused", Detail: reason})
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "account can't sign in")
		return
	}
	now := s.now()
	access, err := s.kv.newSecret(ctx, accessKey, grant{ClientID: c.ID, AccountID: p.ID, Scopes: g.Scopes, AuthTime: g.AuthTime}, accessTTL)
	if err != nil {
		log.Printf("token: %v", err)
		tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
		return
	}
	resp := tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(accessTTL.Seconds()), Scope: strings.Join(g.Scopes, " ")}
	if slices.Contains(g.Scopes, "openid") {
		claims := idClaims{Iss: s.cfg.issuer, Sub: p.ID, Aud: c.ID, Exp: now.Add(idTokenTTL).Unix(), Iat: now.Unix(),
			AuthTime: g.AuthTime, Nonce: g.Nonce, userClaims: claimsOf(p, g.Scopes)}
		if resp.IDToken, err = s.keys.sign(claims); err != nil {
			log.Printf("sign: %v", err)
			tokenFail(w, http.StatusInternalServerError, "server_error", "")
			return
		}
	}
	if slices.Contains(g.Scopes, "offline_access") {
		next := grant{ClientID: c.ID, AccountID: p.ID, Scopes: g.Scopes, AuthTime: g.AuthTime}
		if resp.RefreshToken, err = s.kv.newSecret(ctx, refreshKey, next, s.cfg.refreshTTL); err != nil {
			log.Printf("token: %v", err)
			tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
			return
		}
	}
	if refresh {
		s.auditLog(ctx, auditEntry{AccountID: p.ID, Acct: p.Username, ClientID: c.ID, Event: "refresh"})
	}
	writeJSON(w, http.StatusOK, resp)
}

// userClaims are the claims about the person, by scope.
type userClaims struct {
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Name              string   `json:"name,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Role              string   `json:"role,omitempty"`
}

func claimsOf(p person, scopes []string) userClaims {
	var u userClaims
	if slices.Contains(scopes, "profile") {
		u.PreferredUsername, u.Name, u.Picture, u.Profile = p.Username, p.Name, p.Avatar, p.URL
	}
	if slices.Contains(scopes, "email") {
		verified := p.Confirmed
		u.Email, u.EmailVerified = p.Email, &verified
	}
	if (slices.Contains(scopes, "profile") || slices.Contains(scopes, "groups")) && p.Role != "" {
		u.Groups, u.Role = []string{p.Role}, p.Role
	}
	return u
}

// --- userinfo ---------------------------------------------------------------

func (s *server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found && r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		if err := r.ParseForm(); err == nil {
			token = r.PostForm.Get("access_token")
		}
	}
	unauthorized := func() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, tokenError{Error: "invalid_token"})
	}
	token = strings.TrimSpace(token)
	if token == "" {
		unauthorized()
		return
	}
	ctx := r.Context()
	var g grant
	err := s.kv.get(ctx, accessKey+hashID(token), &g)
	if errors.Is(err, errMissing) {
		unauthorized()
		return
	}
	if err != nil {
		log.Printf("userinfo: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, tokenError{Error: "temporarily_unavailable"})
		return
	}
	if s.clients[g.ClientID] == nil {
		unauthorized()
		return
	}
	p, err := s.person(ctx, g.AccountID, false)
	if errors.Is(err, errNoAccount) || err == nil && p.refusal(s.cfg.allowSilenced) != "" {
		unauthorized()
		return
	}
	if err != nil {
		log.Printf("admin account %s: %v", g.AccountID, err)
		writeJSON(w, http.StatusServiceUnavailable, tokenError{Error: "temporarily_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Sub string `json:"sub"`
		userClaims
	}{p.ID, claimsOf(p, g.Scopes)})
}

// --- logout -----------------------------------------------------------------

// handleLogout ends the session here. It redirects only to a URI registered as
// post_logout_redirect_uri of the client named by the id_token_hint or client_id.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	}
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "bad_request")
		return
	}
	lang := uiLocale(r.Form.Get("ui_locales"))
	ctx := r.Context()
	sess, ok, err := s.currentSession(r)
	if err != nil {
		log.Printf("session: %v", err)
	}
	clientID := r.Form.Get("client_id")
	hintOK := true
	if hint := r.Form.Get("id_token_hint"); hint != "" {
		var claims idClaims
		if err := s.keys.verify(hint, &claims); err != nil || claims.Iss != s.cfg.issuer ||
			(clientID != "" && clientID != claims.Aud) || (ok && claims.Sub != sess.AccountID) {
			hintOK = false
		} else {
			clientID = claims.Aud
		}
	}
	if ok {
		s.endSession(w, r, sess)
		s.auditLog(ctx, auditEntry{AccountID: sess.AccountID, ClientID: clientID, Event: "logout"})
	} else {
		s.clearCookie(w, sessionCookie)
	}
	target := r.Form.Get("post_logout_redirect_uri")
	if c := s.clients[clientID]; target != "" && hintOK && c != nil && c.allowsLogoutRedirect(target) {
		u, _ := url.Parse(target)
		q := u.Query()
		if st := r.Form.Get("state"); st != "" {
			q.Set("state", st)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	v := s.view(r, lang)
	s.render(w, "logout.html", http.StatusOK, v)
}
