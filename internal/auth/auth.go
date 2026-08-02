// Package auth handles password hashing, JWT sessions, and API-key credentials
// backed by the persistent store.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"pubapi/internal/store"
)

// Errors surfaced to callers.
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrBadKey       = errors.New("invalid api key")
)

// keyPrefix marks PubAPI-issued API keys.
const keyPrefix = "pk_"

// Service provides authentication backed by the store.
type Service struct {
	store   *store.Store
	secret  []byte
	jwtTTL  time.Duration
	enabled bool // whether the recon/scan API requires a credential
}

// NewService builds the auth service. When apiAuth is enabled but no JWT secret
// is provided, a random ephemeral secret is generated.
func NewService(st *store.Store, secret string, ttl time.Duration, apiAuth bool) *Service {
	if secret == "" {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		secret = hex.EncodeToString(buf)
		log.Println("auth: JWT_SECRET not set — using a random ephemeral secret (sessions reset on restart)")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{store: st, secret: []byte(secret), jwtTTL: ttl, enabled: apiAuth}
}

// APIAuthEnabled reports whether recon/scan endpoints require a credential.
func (s *Service) APIAuthEnabled() bool { return s.enabled }

// ---- Passwords ----

// HashPassword returns a bcrypt hash of the password.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword reports whether pw matches the stored hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ---- JWT sessions ----

// Claims is the JWT payload for a logged-in dashboard user.
type Claims struct {
	jwt.RegisteredClaims
	Role  string `json:"role"`
	Email string `json:"email"`
}

// IssueJWT signs a session token for a user.
func (s *Service) IssueJWT(u *store.User) (string, time.Time, error) {
	exp := time.Now().Add(s.jwtTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(u.ID, 10),
			Issuer:    "pubapi",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Role:  u.Role,
		Email: u.Email,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.secret)
	return signed, exp, err
}

// TTLSeconds is the session lifetime in seconds.
func (s *Service) TTLSeconds() int { return int(s.jwtTTL.Seconds()) }

// VerifyJWT validates a session token and returns its claims.
func (s *Service) VerifyJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// ---- API keys ----

// hashKey returns the storage hash for an API key's plaintext.
func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GenerateAPIKey mints a new key, returning its plaintext (shown once), a
// display prefix, and the hash to persist.
func GenerateAPIKey() (plaintext, prefix, keyHash string) {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	plaintext = keyPrefix + hex.EncodeToString(buf)
	prefix = plaintext[:len(keyPrefix)+6] // e.g. "pk_ab12cd"
	keyHash = hashKey(plaintext)
	return
}

// ResolveKey validates an API key's plaintext against the store and records use.
func (s *Service) ResolveKey(plaintext string) (*store.APIKeyOwner, error) {
	if !strings.HasPrefix(plaintext, keyPrefix) {
		return nil, ErrBadKey
	}
	owner, err := s.store.ResolveAPIKey(hashKey(plaintext))
	if err != nil {
		return nil, ErrBadKey
	}
	s.store.TouchAPIKey(owner.KeyID)
	return owner, nil
}

// ---- Request authentication for the API surface ----

// AuthenticateAPI resolves a request's credential (X-API-Key or Bearer) to a
// principal string used for logging and access control.
func (s *Service) AuthenticateAPI(r *http.Request) (string, error) {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		if owner, err := s.ResolveKey(k); err == nil {
			return "key:" + strconv.FormatInt(owner.KeyID, 10), nil
		}
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authz, "Bearer ") {
		cred := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if strings.HasPrefix(cred, keyPrefix) {
			if owner, err := s.ResolveKey(cred); err == nil {
				return "key:" + strconv.FormatInt(owner.KeyID, 10), nil
			}
		} else if claims, err := s.VerifyJWT(cred); err == nil {
			return "user:" + claims.Subject, nil
		}
	}
	return "", ErrUnauthorized
}

// UserFromRequest resolves a Bearer JWT to its claims (dashboard endpoints).
func (s *Service) UserFromRequest(r *http.Request) (*Claims, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authz, "Bearer ") {
		return nil, ErrUnauthorized
	}
	claims, err := s.VerifyJWT(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer ")))
	if err != nil {
		return nil, ErrUnauthorized
	}
	return claims, nil
}
