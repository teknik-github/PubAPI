package store

// LogEntry is a single recorded API request.
type LogEntry struct {
	ID        int64  `json:"id"`
	TS        string `json:"ts"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query,omitempty"`
	Status    int    `json:"status"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent,omitempty"`
	Principal string `json:"principal"`
	LatencyMS int64  `json:"latency_ms"`
}

// InsertLog records one request. Errors are ignored by callers (best-effort).
func (s *Store) InsertLog(e LogEntry) error {
	_, err := s.db.Exec(`
        INSERT INTO request_logs (ts, method, path, query, status, ip, user_agent, principal, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.Method, e.Path, e.Query, e.Status, e.IP, e.UserAgent, e.Principal, e.LatencyMS)
	return err
}

// ListLogs returns recent logs, newest first, optionally filtered by principal.
func (s *Store) ListLogs(limit, offset int, principal string) ([]LogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, ts, method, path, query, status, ip, user_agent, principal, latency_ms
              FROM request_logs`
	args := []any{}
	if principal != "" {
		query += ` WHERE principal = ?`
		args = append(args, principal)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogEntry{}
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Method, &e.Path, &e.Query, &e.Status,
			&e.IP, &e.UserAgent, &e.Principal, &e.LatencyMS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LogStats is an aggregate usage summary.
type LogStats struct {
	TotalRequests    int64            `json:"total_requests"`
	UniquePrincipals int              `json:"unique_principals"`
	TopPaths         []Count          `json:"top_paths"`
	TopPrincipals    []Count          `json:"top_principals"`
	StatusCounts     map[string]int64 `json:"status_counts"`
}

// Count is a label/value pair for aggregates.
type Count struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// Stats computes an aggregate summary over all request logs.
func (s *Store) Stats() (*LogStats, error) {
	st := &LogStats{StatusCounts: map[string]int64{}, TopPaths: []Count{}, TopPrincipals: []Count{}}

	if err := s.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT principal) FROM request_logs`).
		Scan(&st.TotalRequests, &st.UniquePrincipals); err != nil {
		return nil, err
	}

	var err error
	if st.TopPaths, err = s.topCounts(`SELECT path, COUNT(*) c FROM request_logs GROUP BY path ORDER BY c DESC LIMIT 10`); err != nil {
		return nil, err
	}
	if st.TopPrincipals, err = s.topCounts(`SELECT principal, COUNT(*) c FROM request_logs GROUP BY principal ORDER BY c DESC LIMIT 10`); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`SELECT (status/100)||'xx' AS bucket, COUNT(*) FROM request_logs GROUP BY bucket`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket string
		var n int64
		if err := rows.Scan(&bucket, &n); err != nil {
			return nil, err
		}
		st.StatusCounts[bucket] = n
	}
	return st, rows.Err()
}

func (s *Store) topCounts(query string) ([]Count, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Label, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
