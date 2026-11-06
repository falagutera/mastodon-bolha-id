package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	oauthScope   = "profile" // only who the person is: the token is revoked right away
	maxAPIBody   = 256 << 10
	errAPIStatus = "instance answered %s %d"
)

var (
	errNoAccount   = errors.New("account not found")
	errRateLimited = errors.New("instance rate limit (429)")
)

// apiError is any answer but 200. Callers decide what a status means; by
// default it is a transient upstream failure.
type apiError struct {
	path   string
	status int
	body   []byte
}

func (e *apiError) Error() string { return fmt.Sprintf(errAPIStatus, e.path, e.status) }

// mastodon talks to the instance: the sign-in app (client id/secret) for the
// person's identity, and the service token for the account status and e-mail.
type mastodon struct {
	base         string
	clientID     string
	clientSecret string
	redirect     string
	adminToken   string
	client       *http.Client
}

func (m *mastodon) authorizeURL(state, verifier string, forceLogin bool) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {m.redirect},
		"scope":                 {oauthScope},
		"state":                 {state},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
	}
	if forceLogin {
		q.Set("force_login", "true")
	}
	return m.base + "/oauth/authorize?" + q.Encode()
}

func (m *mastodon) do(req *http.Request, out any) error {
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		log.Printf("instance rate limit on %s (429, retry after %q)", req.URL.Path, resp.Header.Get("Retry-After"))
		return errRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &apiError{path: req.URL.Path, status: resp.StatusCode, body: body}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(out)
}

func (m *mastodon) exchangeCode(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {m.clientID},
		"client_secret": {m.clientSecret},
		"redirect_uri":  {m.redirect},
		"code_verifier": {verifier},
		"scope":         {oauthScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := m.do(req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("empty access token")
	}
	return out.AccessToken, nil
}

// whoami returns the account id of the person's token. The profile scope allows
// verify_credentials since Mastodon 4.3.
func (m *mastodon) whoami(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/api/v1/accounts/verify_credentials", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	var out struct {
		ID string `json:"id"`
	}
	if err := m.do(req, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("empty account id")
	}
	return out.ID, nil
}

// revoke drops the person's token: it was only needed to learn who they are.
func (m *mastodon) revoke(token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	form := url.Values{"client_id": {m.clientID}, "client_secret": {m.clientSecret}, "token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return m.do(req, nil)
}

// adminAccount is the part of GET /api/v1/admin/accounts/:id this app uses.
type adminAccount struct {
	ID        string  `json:"id"`
	Username  string  `json:"username"`
	Domain    *string `json:"domain"`
	Email     string  `json:"email"`
	Confirmed bool    `json:"confirmed"`
	Approved  bool    `json:"approved"`
	Disabled  bool    `json:"disabled"`
	Suspended bool    `json:"suspended"`
	Silenced  bool    `json:"silenced"`
	Role      *struct {
		ID json.RawMessage `json:"id"` // a string in the API, a number in some versions
	} `json:"role"`
	Account struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		URL         string `json:"url"`
		Avatar      string `json:"avatar"`
	} `json:"account"`
}

func (m *mastodon) adminAccount(ctx context.Context, id string) (adminAccount, error) {
	var a adminAccount
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/api/v1/admin/accounts/"+url.PathEscape(id), nil)
	if err != nil {
		return a, err
	}
	req.Header.Set("Authorization", "Bearer "+m.adminToken)
	if err := m.do(req, &a); err != nil {
		// Only Mastodon's own "record not found" means the account is gone: a 404
		// from a proxy or a maintenance page is a transient failure.
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusNotFound {
			var body struct {
				Error *string `json:"error"`
			}
			if json.Unmarshal(ae.body, &body) == nil && body.Error != nil {
				return a, errNoAccount
			}
		}
		return a, err
	}
	if a.ID != id {
		return a, errors.New("admin API returned another account")
	}
	return a, nil
}

// person is what the app keeps about an account: the status flags and claims.
type person struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Avatar    string `json:"avatar"`
	URL       string `json:"url"`
	Email     string `json:"email"`
	RoleID    string `json:"role_id"`
	Local     bool   `json:"local"`
	Confirmed bool   `json:"confirmed"`
	Approved  bool   `json:"approved"`
	Disabled  bool   `json:"disabled"`
	Suspended bool   `json:"suspended"`
	Silenced  bool   `json:"silenced"`
	// Cache bookkeeping: when it was read from the instance, and whether the
	// instance said the account doesn't exist (a short negative cache).
	CachedAt int64 `json:"cached_at"`
	Missing  bool  `json:"missing,omitempty"`
}

func personOf(a adminAccount) person {
	p := person{
		ID: a.ID, Username: a.Username, Name: a.Account.DisplayName, Avatar: a.Account.Avatar, URL: a.Account.URL,
		Email: a.Email, Local: a.Domain == nil || *a.Domain == "",
		Confirmed: a.Confirmed, Approved: a.Approved, Disabled: a.Disabled, Suspended: a.Suspended, Silenced: a.Silenced,
	}
	if p.Name == "" {
		p.Name = p.Username
	}
	if a.Role != nil {
		p.RoleID = strings.Trim(string(a.Role.ID), `"`)
	}
	return p
}

// refusal says why an account can't sign in, or "" when it can.
func (p person) refusal(allowSilenced bool) string {
	switch {
	case !p.Local:
		return "remote"
	case p.Suspended:
		return "suspended"
	case p.Disabled:
		return "disabled"
	case !p.Approved:
		return "unapproved"
	case !p.Confirmed:
		return "unconfirmed"
	case p.Email == "":
		return "no_email"
	case p.Silenced && !allowSilenced:
		return "silenced"
	}
	return ""
}
