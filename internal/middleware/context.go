package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// contextWithTimeout derives a cancellable context from the request.
func contextWithTimeout(c *gin.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), d)
}
