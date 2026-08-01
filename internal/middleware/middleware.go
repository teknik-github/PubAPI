package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
)

// CORS allows cross-origin browser access to the public API.
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// SecurityHeaders sets conservative response headers on every reply.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

// Recovery converts panics into a clean 500 envelope instead of crashing.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, _ any) {
		response.Abort(c, 500, "internal_error", "An unexpected error occurred.")
	})
}

// Timeout is a lightweight guard that records a request deadline for handlers
// to honor via c.Request.Context(). Gin itself does not cancel the handler,
// but downstream network calls use this context and will abort on timeout.
func Timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := contextWithTimeout(c, d)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
