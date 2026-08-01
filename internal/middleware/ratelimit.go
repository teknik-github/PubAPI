package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"pubapi/internal/response"
)

// visitor tracks a single client's limiter and last-seen time for cleanup.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// ipRateLimiter keeps a per-IP token-bucket limiter with idle eviction.
type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	l := &ipRateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go l.cleanupLoop()
	return l
}

func (l *ipRateLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, ok := l.visitors[ip]
	if !ok {
		lim := rate.NewLimiter(l.rps, l.burst)
		l.visitors[ip] = &visitor{limiter: lim, lastSeen: time.Now()}
		return lim
	}
	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupLoop periodically drops visitors that have been idle for a while,
// keeping memory bounded for a long-running public service.
func (l *ipRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		for ip, v := range l.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

// RateLimit returns a Gin middleware enforcing a per-IP request rate.
func RateLimit(rps float64, burst int) gin.HandlerFunc {
	limiter := newIPRateLimiter(rps, burst)
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.get(ip).Allow() {
			c.Header("Retry-After", "1")
			response.Abort(c, http.StatusTooManyRequests, "rate_limited",
				"Too many requests. Please slow down.")
			return
		}
		c.Next()
	}
}
