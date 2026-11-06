package main

import (
	"errors"
	"log"
	"net/http"
)

// startLogin sends the browser to the instance to sign in. The state is bound
// to this browser by a cookie and to the waiting authorization request.
func (s *server) startLogin(w http.ResponseWriter, r *http.Request, requestID string, force bool, lang string) {
	state, verifier := randomToken(), randomToken()
	if err := s.kv.put(r.Context(), loginKey+hashID(state), pendingLogin{Verifier: verifier, RequestID: requestID}, loginTTL); err != nil {
		log.Printf("login: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", lang)
		return
	}
	s.setCookie(w, stateCookie, state, loginTTL)
	http.Redirect(w, r, s.api.authorizeURL(state, verifier, force), http.StatusFound)
}

// handleCallback finishes the sign-in on the instance: who the person is, then
// whether the account may sign in, then a session here.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(stateCookie)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "expired")
		return
	}
	s.clearCookie(w, stateCookie)
	q := r.URL.Query()
	if !equal(q.Get("state"), c.Value) {
		s.renderError(w, r, http.StatusBadRequest, "expired")
		return
	}
	var pending pendingLogin
	err = s.kv.take(ctx, loginKey+hashID(c.Value), &pending)
	if errors.Is(err, errMissing) {
		s.renderError(w, r, http.StatusBadRequest, "expired")
		return
	}
	if err != nil {
		log.Printf("callback: %v", err)
		s.renderError(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	var req authRequest
	err = s.kv.get(ctx, requestKey+hashID(pending.RequestID), &req)
	if errors.Is(err, errMissing) {
		s.renderError(w, r, http.StatusBadRequest, "expired")
		return
	}
	if err != nil {
		log.Printf("callback: %v", err)
		s.renderError(w, r, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if q.Get("code") == "" {
		// Denied or failed on the instance: tell the client.
		s.kv.del(ctx, requestKey+hashID(pending.RequestID))
		s.redirectError(w, r, req.RedirectURI, req.State, "access_denied", "", http.StatusFound)
		return
	}
	token, err := s.api.exchangeCode(ctx, q.Get("code"), pending.Verifier)
	if err != nil {
		log.Printf("token exchange: %v", err)
		s.renderErrorLang(w, r, http.StatusBadGateway, "instance", req.Lang)
		return
	}
	accountID, err := s.api.whoami(ctx, token)
	// Only the identity was needed: drop the person's token right away.
	if rerr := s.api.revoke(token); rerr != nil {
		log.Printf("revoke: %v", rerr)
	}
	if err != nil {
		log.Printf("verify_credentials: %v", err)
		s.renderErrorLang(w, r, http.StatusBadGateway, "instance", req.Lang)
		return
	}
	p, err := s.person(ctx, accountID, true)
	if err != nil && !errors.Is(err, errNoAccount) {
		log.Printf("admin account %s: %v", accountID, err)
		s.renderErrorLang(w, r, http.StatusBadGateway, "instance", req.Lang)
		return
	}
	reason := "gone"
	if err == nil {
		reason = p.refusal(s.cfg.allowSilenced)
	}
	if reason != "" {
		s.kv.del(ctx, requestKey+hashID(pending.RequestID))
		s.auditLog(ctx, auditEntry{AccountID: accountID, Acct: p.Username, ClientID: req.ClientID, Event: "refused", Detail: reason})
		s.renderErrorLang(w, r, http.StatusForbidden, refusalKey(reason), req.Lang)
		return
	}
	// A new session id on every sign-in; the old one, if any, ends.
	if old, ok, _ := s.currentSession(r); ok {
		s.kv.del(ctx, sessionKey+hashID(old.ID))
	}
	sess := session{AccountID: p.ID, AuthTime: s.now().Unix(), CSRF: randomToken()}
	sess.ID, err = s.kv.newSecret(ctx, sessionKey, sess, s.cfg.sessionTTL)
	if err != nil {
		log.Printf("session: %v", err)
		s.renderErrorLang(w, r, http.StatusServiceUnavailable, "unavailable", req.Lang)
		return
	}
	s.setCookie(w, sessionCookie, sess.ID, s.cfg.sessionTTL)
	s.continueAuth(w, r, sess, pending.RequestID, req)
}
