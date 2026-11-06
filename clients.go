package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
)

// client is one application that signs people in here. They come from a JSON
// file (ID_CLIENTS_FILE), see clients.example.json.
type client struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Confidential clients authenticate at /token with one of these: the
	// SHA-256 (hex) of the secret, or the name of an env var that holds it.
	SecretSHA256           string   `json:"secret_sha256,omitempty"`
	SecretEnv              string   `json:"secret_env,omitempty"`
	Public                 bool     `json:"public,omitempty"` // no secret, PKCE S256 required
	Dev                    bool     `json:"dev,omitempty"`    // allows http://localhost redirect URIs
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	secretHash []byte
}

const minSecretLen = 32

type clientList map[string]*client

func loadClients(path string) (clientList, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path set by the operator (ID_CLIENTS_FILE)
	if err != nil {
		return nil, err
	}
	return parseClients(data, os.Getenv)
}

func parseClients(data []byte, getenv func(string) string) (clientList, error) {
	var file struct {
		Clients []*client `json:"clients"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("clients file: %w", err)
	}
	out := clientList{}
	for i, c := range file.Clients {
		if c.ID == "" || c.Name == "" {
			return nil, fmt.Errorf("client %d: id and name are required", i)
		}
		if _, dup := out[c.ID]; dup {
			return nil, fmt.Errorf("client %q: duplicate id", c.ID)
		}
		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client %q: redirect_uris is required", c.ID)
		}
		for _, u := range append(slices.Clone(c.RedirectURIs), c.PostLogoutRedirectURIs...) {
			if err := checkRedirect(u, c.Dev); err != nil {
				return nil, fmt.Errorf("client %q: %s: %w", c.ID, u, err)
			}
		}
		switch {
		case c.Public && (c.SecretSHA256 != "" || c.SecretEnv != ""):
			return nil, fmt.Errorf("client %q: a public client has no secret", c.ID)
		case c.Public:
		case c.SecretSHA256 != "" && c.SecretEnv != "":
			return nil, fmt.Errorf("client %q: set secret_sha256 or secret_env, not both", c.ID)
		case c.SecretSHA256 != "":
			h, err := hex.DecodeString(c.SecretSHA256)
			if err != nil || len(h) != sha256.Size {
				return nil, fmt.Errorf("client %q: secret_sha256 must be 64 hex characters", c.ID)
			}
			c.secretHash = h
		case c.SecretEnv != "":
			s := getenv(c.SecretEnv)
			if len(s) < minSecretLen {
				return nil, fmt.Errorf("client %q: %s must hold a secret of at least %d characters", c.ID, c.SecretEnv, minSecretLen)
			}
			sum := sha256.Sum256([]byte(s))
			c.secretHash = sum[:]
		default:
			return nil, fmt.Errorf("client %q: a confidential client needs secret_sha256 or secret_env (or set public)", c.ID)
		}
		out[c.ID] = c
	}
	return out, nil
}

// checkRedirect allows https, or http on loopback for clients marked dev.
func checkRedirect(raw string, dev bool) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("must be an absolute URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not have a fragment")
	}
	if u.User != nil {
		return fmt.Errorf("must not have credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); !dev || h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return fmt.Errorf("http is only allowed on loopback, for a client with \"dev\": true")
		}
	default:
		return fmt.Errorf("scheme must be https")
	}
	return nil
}

func (c *client) checkSecret(secret string) bool {
	if c.Public || len(c.secretHash) == 0 {
		return false
	}
	sum := sha256.Sum256([]byte(secret))
	return equal(string(sum[:]), string(c.secretHash))
}

// Redirect URIs are compared exactly, as registered.
func (c *client) allowsRedirect(u string) bool { return slices.Contains(c.RedirectURIs, u) }

func (c *client) allowsLogoutRedirect(u string) bool {
	return slices.Contains(c.PostLogoutRedirectURIs, u)
}

// origin of a registered redirect URI, for the consent page's form-action.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
