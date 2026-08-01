// Package auth provides optional API-key and JWT authentication.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Authenticator validates API keys and issues/verifies JWTs.
type Authenticator struct {
	enabled bool
	keys    []string
	secret  []byte
	ttl     time.Duration
}

// ErrUnauthorized is returned when a request carries no valid credential.
var ErrUnauthorized = errors.New("unauthorized")

// New builds an Authenticator. When auth is enabled but no JWT secret is set,
// a random ephemeral secret is generated (tokens won't survive a restart).
func New(enabled bool, keys []string, secret string, ttl time.Duration) *Authenticator {
	a := &Authenticator{enabled: enabled, keys: keys, ttl: ttl}
	if !enabled {
		return a
	}
	if secret == "" {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		secret = hex.EncodeToString(buf)
		log.Println("auth: JWT_SECRET not set — using a random ephemeral secret (tokens reset on restart)")
	}
	a.secret = []byte(secret)
	if ttl <= 0 {
		a.ttl = time.Hour
	}
	if len(keys) == 0 {
		log.Println("auth: AUTH_ENABLED but no AUTH_API_KEYS configured — the token endpoint cannot mint tokens")
	}
	return a
}

// Enabled reports whether authentication is active.
func (a *Authenticator) Enabled() bool { return a.enabled }

// TTL is the lifetime of issued tokens.
func (a *Authenticator) TTL() time.Duration { return a.ttl }

// ValidKey reports whether key matches a configured API key (constant-time).
func (a *Authenticator) ValidKey(key string) bool {
	if key == "" {
		return false
	}
	for _, k := range a.keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

// Issue mints a signed JWT for the given subject.
func (a *Authenticator) Issue(subject string) (string, time.Time, error) {
	exp := time.Now().Add(a.ttl)
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    "pubapi",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(a.secret)
	return signed, exp, err
}

// VerifyToken validates a JWT and returns its subject.
func (a *Authenticator) VerifyToken(tokenStr string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return a.secret, nil
	})
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// Authenticate inspects a request for a valid credential and returns the
// principal it authenticated as. Order: X-API-Key, then Authorization: Bearer
// (tried as an API key, then as a JWT).
func (a *Authenticator) Authenticate(r *http.Request) (string, error) {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" && a.ValidKey(k) {
		return "apikey", nil
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authz, "Bearer ") {
		cred := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if a.ValidKey(cred) {
			return "apikey", nil
		}
		if sub, err := a.VerifyToken(cred); err == nil {
			return sub, nil
		}
	}
	return "", ErrUnauthorized
}
