package store

import (
	"database/sql"
	"errors"
)

// APIKey is a client-issued credential for calling the API. The plaintext key
// is never stored — only its hash, plus a short prefix for display.
type APIKey struct {
	ID         int64   `json:"id"`
	UserID     int64   `json:"user_id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	Revoked    bool    `json:"revoked"`
}

// CreateAPIKey stores a new key (by hash) for a user.
func (s *Store) CreateAPIKey(userID int64, name, prefix, keyHash string) (*APIKey, error) {
	res, err := s.db.Exec(
		`INSERT INTO api_keys (user_id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		userID, name, prefix, keyHash, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &APIKey{ID: id, UserID: userID, Name: name, Prefix: prefix, CreatedAt: now()}, nil
}

// APIKeyOwner is the result of resolving a live key hash to its owner.
type APIKeyOwner struct {
	KeyID  int64
	UserID int64
	Role   string
	Email  string
}

// ResolveAPIKey looks up an unrevoked key by hash and returns its owner.
func (s *Store) ResolveAPIKey(keyHash string) (*APIKeyOwner, error) {
	var o APIKeyOwner
	err := s.db.QueryRow(`
        SELECT k.id, u.id, u.role, u.email
        FROM api_keys k JOIN users u ON u.id = k.user_id
        WHERE k.key_hash = ? AND k.revoked = 0`, keyHash).
		Scan(&o.KeyID, &o.UserID, &o.Role, &o.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// TouchAPIKey records the last-used timestamp for a key.
func (s *Store) TouchAPIKey(id int64) {
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now(), id)
}

// ListAPIKeysByUser returns a user's keys, newest first.
func (s *Store) ListAPIKeysByUser(userID int64) ([]APIKey, error) {
	rows, err := s.db.Query(`
        SELECT id, user_id, name, prefix, created_at, last_used_at, revoked
        FROM api_keys WHERE user_id = ? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var rev int
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &rev); err != nil {
			return nil, err
		}
		k.Revoked = rev == 1
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks a key revoked if it belongs to the given user.
func (s *Store) RevokeAPIKey(id, userID int64) error {
	res, err := s.db.Exec(`UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
