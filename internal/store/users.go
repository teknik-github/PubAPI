package store

import (
	"database/sql"
	"errors"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// User is an account that can log in to the dashboard.
type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	AcceptedTOS  bool   `json:"accepted_tos"`
	CreatedAt    string `json:"created_at"`
}

// CreateUser inserts a new user and returns it with its assigned ID.
func (s *Store) CreateUser(email, passwordHash, role string, acceptedTOS bool) (*User, error) {
	tos := 0
	if acceptedTOS {
		tos = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO users (email, password_hash, role, accepted_tos, created_at) VALUES (?, ?, ?, ?, ?)`,
		email, passwordHash, role, tos, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetUserByID(id)
}

// GetUserByEmail looks up a user by email.
func (s *Store) GetUserByEmail(email string) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, role, accepted_tos, created_at FROM users WHERE email = ?`, email))
}

// GetUserByID looks up a user by id.
func (s *Store) GetUserByID(id int64) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, role, accepted_tos, created_at FROM users WHERE id = ?`, id))
}

func (s *Store) scanUser(row *sql.Row) (*User, error) {
	var u User
	var tos int
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &tos, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.AcceptedTOS = tos == 1
	return &u, nil
}

// ListUsers returns all users with their API-key counts, newest first.
func (s *Store) ListUsers() ([]UserSummary, error) {
	rows, err := s.db.Query(`
        SELECT u.id, u.email, u.role, u.created_at,
               (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id AND k.revoked = 0)
        FROM users u ORDER BY u.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserSummary{}
	for rows.Next() {
		var us UserSummary
		if err := rows.Scan(&us.ID, &us.Email, &us.Role, &us.CreatedAt, &us.ActiveKeys); err != nil {
			return nil, err
		}
		out = append(out, us)
	}
	return out, rows.Err()
}

// UserSummary is the admin-facing view of a user.
type UserSummary struct {
	ID         int64  `json:"id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	ActiveKeys int    `json:"active_keys"`
}

// DeleteUser removes a user (cascading to their API keys). Request logs are
// intentionally retained for audit history.
func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAdmins returns how many admin users exist.
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}
