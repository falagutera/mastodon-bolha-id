package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Short-lived state lives in Redis with a TTL, so any replica can serve any
// step. Keys hold the SHA-256 of the secret value, never the value itself.
const (
	requestKey = "id:req:"
	loginKey   = "id:login:"
	sessionKey = "id:sess:"
	codeKey    = "id:code:"
	accessKey  = "id:at:"
	refreshKey = "id:rt:"
	personKey  = "id:person:"
	requestTTL = 10 * time.Minute
	loginTTL   = 10 * time.Minute
	codeTTL    = 60 * time.Second
	accessTTL  = 10 * time.Minute
	idTokenTTL = 10 * time.Minute
	personTTL  = 5 * time.Minute
)

var errMissing = errors.New("not found or expired")

// authRequest is a validated /authorize request waiting for sign-in or consent.
type authRequest struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	State       string   `json:"state,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`
	Challenge   string   `json:"challenge,omitempty"`
	Prompt      string   `json:"prompt,omitempty"`
	Lang        string   `json:"lang,omitempty"` // from ui_locales
	// AccountID binds the request to the session that saw the consent page.
	AccountID string `json:"account_id,omitempty"`
}

// pendingLogin is the round trip to the instance.
type pendingLogin struct {
	Verifier  string `json:"verifier"`
	RequestID string `json:"request_id"`
}

type session struct {
	ID        string `json:"-"`
	AccountID string `json:"account_id"`
	AuthTime  int64  `json:"auth_time"`
	CSRF      string `json:"csrf"`
}

// grant is what a code, an access token or a refresh token stands for.
type grant struct {
	ClientID    string   `json:"client_id"`
	AccountID   string   `json:"account_id"`
	Scopes      []string `json:"scopes"`
	AuthTime    int64    `json:"auth_time"`
	RedirectURI string   `json:"redirect_uri,omitempty"` // codes only
	Challenge   string   `json:"challenge,omitempty"`    // codes only
	Nonce       string   `json:"nonce,omitempty"`        // codes and refresh
}

type kv struct{ rdb *redis.Client }

func (k kv) put(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return k.rdb.Set(ctx, key, b, ttl).Err()
}

func (k kv) get(ctx context.Context, key string, v any) error {
	b, err := k.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return errMissing
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// take reads and deletes in one step: a code or token works once, even with
// two replicas racing.
func (k kv) take(ctx context.Context, key string, v any) error {
	b, err := k.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return errMissing
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (k kv) del(ctx context.Context, key string) error { return k.rdb.Del(ctx, key).Err() }

// newSecret stores v under a fresh random value and returns that value.
func (k kv) newSecret(ctx context.Context, prefix string, v any, ttl time.Duration) (string, error) {
	id := randomToken()
	return id, k.put(ctx, prefix+hashID(id), v, ttl)
}
