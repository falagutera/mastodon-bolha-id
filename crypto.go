package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashID is what is stored for a secret value (session, code, token): reading
// Redis doesn't give anything that can be presented back to the app.
func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// s256 is the PKCE S256 transform of a verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
