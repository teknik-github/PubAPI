package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"pubapi/internal/store"
)

// RequestLogger persists API requests to the store for admin visibility.
// Writes are asynchronous and best-effort: if the buffer is full the entry is
// dropped rather than slowing the request path.
type RequestLogger struct {
	store *store.Store
	ch    chan store.LogEntry
}

// NewRequestLogger starts the background writer.
func NewRequestLogger(st *store.Store) *RequestLogger {
	rl := &RequestLogger{store: st, ch: make(chan store.LogEntry, 2048)}
	go rl.run()
	return rl
}

func (rl *RequestLogger) run() {
	for e := range rl.ch {
		if err := rl.store.InsertLog(e); err != nil {
			log.Printf("request log insert failed: %v", err)
		}
	}
}

// Middleware records each request once the handler chain completes.
func (rl *RequestLogger) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		principal := "anon"
		if p := c.GetString(CtxPrincipal); p != "" {
			principal = p
		}
		entry := store.LogEntry{
			TS:        time.Now().UTC().Format(time.RFC3339),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Query:     c.Request.URL.RawQuery,
			Status:    c.Writer.Status(),
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Principal: principal,
			LatencyMS: time.Since(start).Milliseconds(),
		}
		select {
		case rl.ch <- entry:
		default: // buffer full — drop rather than block
		}
	}
}
