package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Refresh limits per minute. The account limit catches a looping client for one
// person; the client limit caps what one client can make us ask the instance.
const (
	refreshPerAccount = 30
	refreshPerClient  = 600
	lockWait          = 3 * time.Second
	lockTTL           = 5 * time.Second
)

// --- account status -----------------------------------------------------------

// person returns the account status and claims. A cached answer younger than
// maxAge is used (maxAge 0 always asks the instance). Concurrent callers for the
// same account, on any replica, share one call to the admin API. "The account
// doesn't exist" is cached for missingTTL.
func (s *server) person(ctx context.Context, id string, maxAge time.Duration) (person, error) {
	start := s.now()
	if maxAge > 0 {
		if p, ok := s.cachedPerson(ctx, id, start.Add(-maxAge)); ok {
			return p, p.err()
		}
	}
	locked, err := s.rdb.SetNX(ctx, personLock+id, "1", lockTTL).Result()
	switch {
	case err != nil:
		log.Printf("person lock: %v", err)
	case locked:
		defer s.rdb.Del(context.WithoutCancel(ctx), personLock+id)
	default:
		// Someone else is asking the instance: wait for that answer.
		deadline := start.Add(lockWait)
		for s.now().Before(deadline) {
			select {
			case <-ctx.Done():
				return person{}, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
			if p, ok := s.cachedPerson(ctx, id, start); ok {
				return p, p.err()
			}
		}
	}
	a, err := s.api.adminAccount(ctx, id)
	now := s.now().UnixMilli()
	if errors.Is(err, errNoAccount) {
		gone := person{ID: id, Missing: true, CachedAt: now}
		if err := s.kv.put(ctx, personKey+id, gone, missingTTL); err != nil {
			log.Printf("person cache: %v", err)
		}
		return gone, errNoAccount
	}
	if err != nil {
		return person{}, err
	}
	p := personOf(a)
	p.CachedAt = now
	if err := s.kv.put(ctx, personKey+id, p, personTTL); err != nil {
		log.Printf("person cache: %v", err)
	}
	return p, nil
}

func (s *server) cachedPerson(ctx context.Context, id string, notBefore time.Time) (person, bool) {
	var p person
	err := s.kv.get(ctx, personKey+id, &p)
	if err != nil {
		if !errors.Is(err, errMissing) {
			log.Printf("person cache: %v", err)
		}
		return p, false
	}
	return p, p.CachedAt >= notBefore.UnixMilli()
}

func (p person) err() error {
	if p.Missing {
		return errNoAccount
	}
	return nil
}

// --- token families ---------------------------------------------------------

// track records live token keys under their family, and the family under the account.
func (s *server) track(ctx context.Context, family, accountID string, keys ...string) error {
	pipe := s.rdb.TxPipeline()
	members := make([]any, len(keys))
	for i, k := range keys {
		members[i] = k
	}
	pipe.SAdd(ctx, familyKeys+family, members...)
	pipe.Expire(ctx, familyKeys+family, s.cfg.refreshTTL)
	pipe.SAdd(ctx, accountFams+accountID, family)
	pipe.Expire(ctx, accountFams+accountID, s.cfg.refreshTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// revokeFamily marks the family revoked (checked by userinfo and refresh) and
// deletes its live tokens. The marker outlives every token of the family.
func (s *server) revokeFamily(ctx context.Context, family string) error {
	if family == "" {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	if err := s.rdb.Set(ctx, familyRev+family, "1", s.cfg.refreshTTL).Err(); err != nil {
		return err
	}
	keys, err := s.rdb.SMembers(ctx, familyKeys+family).Result()
	if err != nil {
		return err
	}
	return s.rdb.Del(ctx, append(keys, familyKeys+family)...).Err()
}

func (s *server) familyRevoked(ctx context.Context, family string) (bool, error) {
	if family == "" {
		return true, nil
	}
	n, err := s.rdb.Exists(ctx, familyRev+family).Result()
	return n > 0, err
}

// revokeAccount revokes every family of the account, for sign-out.
func (s *server) revokeAccount(ctx context.Context, accountID string) error {
	fams, err := s.rdb.SMembers(ctx, accountFams+accountID).Result()
	if err != nil {
		return err
	}
	for _, f := range fams {
		if err := s.revokeFamily(ctx, f); err != nil {
			return err
		}
	}
	return s.rdb.Del(context.WithoutCancel(ctx), accountFams+accountID).Err()
}

// consumeScript deletes a code or refresh token and, in the same step, leaves
// a "used" marker that names its family, for replay detection.
var consumeScript = redis.NewScript(`
local v = redis.call('GETDEL', KEYS[1])
if v then
  local ok, g = pcall(cjson.decode, v)
  local fam = ''
  if ok and type(g) == 'table' and g['family'] then fam = g['family'] end
  redis.call('SET', KEYS[2], fam, 'PX', ARGV[1])
end
return v`)

func (s *server) consume(ctx context.Context, key, usedKey string, usedTTL time.Duration, g *grant) error {
	v, err := consumeScript.Run(ctx, s.rdb, []string{key, usedKey}, usedTTL.Milliseconds()).Text()
	if errors.Is(err, redis.Nil) {
		return errMissing
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), g)
}

// replayed handles a code or refresh token that is not live: if it was used
// before, its whole family is revoked.
func (s *server) replayed(ctx context.Context, usedKey, what, clientID string) {
	fam, err := s.rdb.Get(ctx, usedKey).Result()
	if errors.Is(err, redis.Nil) || fam == "" {
		return
	}
	if err != nil {
		log.Printf("replay check: %v", err)
		return
	}
	log.Printf("%s replayed (client %s): revoking its token family", what, clientID)
	if err := s.revokeFamily(ctx, fam); err != nil {
		log.Printf("revoke family: %v", err)
	}
}

// allow counts one request against a per-minute limit.
func (s *server) allow(ctx context.Context, key string, limit int64) (bool, time.Duration, error) {
	pipe := s.rdb.TxPipeline()
	n := pipe.Incr(ctx, rateKey+key)
	pipe.ExpireNX(ctx, rateKey+key, time.Minute)
	ttl := pipe.TTL(ctx, rateKey+key)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, 0, err
	}
	return n.Val() <= limit, ttl.Val(), nil
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

// upstreamFail answers a transient failure of the instance or of Redis.
func upstreamFail(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	tokenFail(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
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
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.codeGrant(w, r, c)
	case "refresh_token":
		s.refreshGrant(w, r, c)
	default:
		tokenFail(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *server) codeGrant(w http.ResponseWriter, r *http.Request, c *client) {
	ctx := r.Context()
	h := hashID(r.PostForm.Get("code"))
	var g grant
	err := s.consume(ctx, codeKey+h, codeUsed+h, codeUsedTTL, &g)
	if errors.Is(err, errMissing) {
		// RFC 6749 4.1.2: a code used twice revokes what it gave.
		s.replayed(ctx, codeUsed+h, "code", c.ID)
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
		return
	}
	if err != nil {
		log.Printf("token: %v", err)
		upstreamFail(w)
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
	p, ok := s.tokenAccount(w, r, c, g, personTTL)
	if !ok {
		return
	}
	s.issueTokens(w, r, c, g, p, false)
}

// refreshGrant validates everything before it consumes the refresh token, so a
// failure of the instance doesn't cost the client its token.
func (s *server) refreshGrant(w http.ResponseWriter, r *http.Request, c *client) {
	ctx := r.Context()
	h := hashID(r.PostForm.Get("refresh_token"))
	var g grant
	err := s.kv.get(ctx, refreshKey+h, &g)
	if errors.Is(err, errMissing) {
		// RFC 9700 4.14.2: a rotated refresh token presented again revokes the family.
		s.replayed(ctx, refreshUsed+h, "refresh token", c.ID)
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired refresh token")
		return
	}
	if err != nil {
		log.Printf("token: %v", err)
		upstreamFail(w)
		return
	}
	if g.ClientID != c.ID {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if revoked, err := s.familyRevoked(ctx, g.Family); err != nil || revoked {
		if err != nil {
			log.Printf("token: %v", err)
			upstreamFail(w)
			return
		}
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "revoked")
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
	for _, lim := range []struct {
		key   string
		limit int64
	}{{"acct:" + g.AccountID, refreshPerAccount}, {"client:" + c.ID, refreshPerClient}} {
		ok, wait, err := s.allow(ctx, lim.key, lim.limit)
		if err != nil {
			log.Printf("rate limit: %v", err)
		}
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(wait.Seconds()))))
			tokenFail(w, http.StatusTooManyRequests, "slow_down", "too many refresh requests")
			return
		}
	}
	p, ok := s.tokenAccount(w, r, c, g, refreshAge)
	if !ok {
		return
	}
	// Now rotate: only one request can consume it.
	scopes := g.Scopes
	if err := s.consume(ctx, refreshKey+h, refreshUsed+h, s.cfg.refreshTTL, &g); err != nil {
		if !errors.Is(err, errMissing) {
			log.Printf("token: %v", err)
			upstreamFail(w)
			return
		}
		// Lost a race with a concurrent refresh of the same token.
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	}
	g.Scopes, g.Nonce = scopes, ""
	s.issueTokens(w, r, c, g, p, true)
}

// tokenAccount checks the account. A transient failure answers 503 and leaves
// the grant alone; a refused account loses the whole token family.
func (s *server) tokenAccount(w http.ResponseWriter, r *http.Request, c *client, g grant, maxAge time.Duration) (person, bool) {
	ctx := r.Context()
	p, err := s.person(ctx, g.AccountID, maxAge)
	if err != nil && !errors.Is(err, errNoAccount) {
		log.Printf("admin account %s: %v", g.AccountID, err)
		upstreamFail(w)
		return p, false
	}
	reason := "gone"
	if err == nil {
		reason = p.refusal(s.cfg.allowSilenced)
	}
	if reason != "" {
		if err := s.revokeFamily(ctx, g.Family); err != nil {
			log.Printf("revoke family: %v", err)
		}
		s.auditLog(ctx, auditEntry{AccountID: g.AccountID, Acct: p.Username, ClientID: c.ID, Event: "refused", Detail: reason})
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "account can't sign in")
		return p, false
	}
	return p, true
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func (s *server) issueTokens(w http.ResponseWriter, r *http.Request, c *client, g grant, p person, refresh bool) {
	ctx := r.Context()
	now := s.now()
	next := grant{ClientID: c.ID, AccountID: p.ID, Scopes: g.Scopes, AuthTime: g.AuthTime, Family: g.Family}
	access, err := s.kv.newSecret(ctx, accessKey, next, accessTTL)
	if err != nil {
		log.Printf("token: %v", err)
		upstreamFail(w)
		return
	}
	keys := []string{accessKey + hashID(access)}
	resp := tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(accessTTL.Seconds()), Scope: strings.Join(g.Scopes, " ")}
	if slices.Contains(g.Scopes, "openid") {
		claims := idClaims{Iss: s.cfg.issuer, Sub: p.ID, Aud: c.ID, Exp: now.Add(idTokenTTL).Unix(), Iat: now.Unix(),
			AuthTime: g.AuthTime, Nonce: g.Nonce, userClaims: s.claimsOf(p, g.Scopes)}
		if resp.IDToken, err = s.keys.sign(claims); err != nil {
			log.Printf("sign: %v", err)
			tokenFail(w, http.StatusInternalServerError, "server_error", "")
			return
		}
	}
	if slices.Contains(g.Scopes, "offline_access") {
		if resp.RefreshToken, err = s.kv.newSecret(ctx, refreshKey, next, s.cfg.refreshTTL); err != nil {
			log.Printf("token: %v", err)
			upstreamFail(w)
			return
		}
		keys = append(keys, refreshKey+hashID(resp.RefreshToken))
	}
	if err := s.track(ctx, g.Family, p.ID, keys...); err != nil {
		log.Printf("token family: %v", err)
		upstreamFail(w)
		return
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

// claimsOf builds the claims. groups/role only come from ID_ROLE_GROUPS: role
// names on the instance are free text and can be renamed.
func (s *server) claimsOf(p person, scopes []string) userClaims {
	var u userClaims
	if slices.Contains(scopes, "profile") {
		u.PreferredUsername, u.Name, u.Picture, u.Profile = p.Username, p.Name, p.Avatar, p.URL
	}
	if slices.Contains(scopes, "email") {
		verified := p.Confirmed
		u.Email, u.EmailVerified = p.Email, &verified
	}
	if group := s.cfg.roleGroups[p.RoleID]; group != "" && p.RoleID != "" &&
		(slices.Contains(scopes, "profile") || slices.Contains(scopes, "groups")) {
		u.Groups, u.Role = []string{group}, group
	}
	return u
}

// --- userinfo ---------------------------------------------------------------

// bearer reads "Authorization: Bearer <token>", the scheme in any case.
func bearer(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(token), true
}

func (s *server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	token, found := bearer(r)
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
	unavailable := func(err error) {
		log.Printf("userinfo: %v", err)
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, tokenError{Error: "temporarily_unavailable"})
	}
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
		unavailable(err)
		return
	}
	if s.clients[g.ClientID] == nil {
		unauthorized()
		return
	}
	if revoked, err := s.familyRevoked(ctx, g.Family); err != nil {
		unavailable(err)
		return
	} else if revoked {
		unauthorized()
		return
	}
	p, err := s.person(ctx, g.AccountID, personTTL)
	if errors.Is(err, errNoAccount) || err == nil && p.refusal(s.cfg.allowSilenced) != "" {
		unauthorized()
		return
	}
	if err != nil {
		unavailable(err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Sub string `json:"sub"`
		userClaims
	}{p.ID, s.claimsOf(p, g.Scopes)})
}

// --- logout -----------------------------------------------------------------

// handleLogout ends the session here and revokes the account's refresh token
// families. It redirects only to a URI registered as post_logout_redirect_uri
// of the client named by the id_token_hint or client_id.
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
	c := s.clients[clientID]
	if ok {
		s.endSession(w, r, sess)
		if err := s.revokeAccount(ctx, sess.AccountID); err != nil {
			log.Printf("logout: revoke tokens: %v", err)
		}
		e := auditEntry{AccountID: sess.AccountID, Event: "logout"}
		if c != nil { // only registered ids reach the log
			e.ClientID = c.ID
		}
		s.auditLog(ctx, e)
	} else {
		s.clearCookie(w, sessionCookie)
	}
	target := r.Form.Get("post_logout_redirect_uri")
	if target != "" && hintOK && c != nil && c.allowsLogoutRedirect(target) {
		u, _ := url.Parse(target)
		q := u.Query()
		if st := r.Form.Get("state"); st != "" {
			q.Set("state", st)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	s.render(w, "logout.html", http.StatusOK, s.view(r, lang))
}
