package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// keySet signs with the current key and publishes the previous one too, so
// tokens signed before a rotation still verify until they expire.
type keySet struct {
	current  *rsa.PrivateKey
	kid      string
	previous *rsa.PublicKey // nil when there is none
	prevKid  string
}

const minKeyBits = 2048

func newKeySet(currentPEM, previousPEM string) (*keySet, error) {
	priv, err := parsePrivateKey(currentPEM)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	ks := &keySet{current: priv, kid: thumbprint(&priv.PublicKey)}
	if strings.TrimSpace(previousPEM) != "" {
		pub, err := parsePublicKey(previousPEM)
		if err != nil {
			return nil, fmt.Errorf("previous signing key: %w", err)
		}
		if kid := thumbprint(pub); kid != ks.kid {
			ks.previous, ks.prevKid = pub, kid
		}
	}
	return ks, nil
}

func parsePrivateKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		key = rk
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	if key.N.BitLen() < minKeyBits {
		return nil, fmt.Errorf("RSA key must have at least %d bits", minKeyBits)
	}
	return key, nil
}

// parsePublicKey accepts a private key too: the previous key is usually the
// old secret moved to another variable.
func parsePublicKey(s string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return pk, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	priv, err := parsePrivateKey(s)
	if err != nil {
		return nil, err
	}
	return &priv.PublicKey, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// thumbprint is the RFC 7638 JWK thumbprint, used as kid.
func thumbprint(pub *rsa.PublicKey) string {
	e := big.NewInt(int64(pub.E)).Bytes()
	j := `{"e":"` + b64(e) + `","kty":"RSA","n":"` + b64(pub.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(j))
	return b64(sum[:])
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func toJWK(pub *rsa.PublicKey, kid string) jwk {
	return jwk{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid, N: b64(pub.N.Bytes()), E: b64(big.NewInt(int64(pub.E)).Bytes())}
}

func (k *keySet) jwks() []byte {
	keys := []jwk{toJWK(&k.current.PublicKey, k.kid)}
	if k.previous != nil {
		keys = append(keys, toJWK(k.previous, k.prevKid))
	}
	b, _ := json.Marshal(map[string][]jwk{"keys": keys})
	return b
}

// sign makes a compact RS256 JWS of the claims.
func (k *keySet) sign(claims any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.current, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// verify checks a JWS made by sign with either key and decodes its claims. It
// doesn't check exp: the logout endpoint accepts expired id_token hints.
func (k *keySet) verify(token string, claims any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16<<10 {
		return errors.New("malformed token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("malformed header")
	}
	var h struct{ Alg, Kid string }
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "RS256" {
		return errors.New("unsupported header")
	}
	var pub *rsa.PublicKey
	switch {
	case h.Kid == k.kid:
		pub = &k.current.PublicKey
	case k.previous != nil && h.Kid == k.prevKid:
		pub = k.previous
	default:
		return errors.New("unknown key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed payload")
	}
	return json.Unmarshal(pb, claims)
}

// idClaims is the id_token. Profile claims are set by scope.
type idClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	AuthTime int64  `json:"auth_time"`
	Nonce    string `json:"nonce,omitempty"`
	userClaims
}

func (c idClaims) expired(now time.Time) bool { return now.Unix() >= c.Exp }
