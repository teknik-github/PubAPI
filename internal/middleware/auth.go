package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/response"
)

// Auth enforces authentication when the authenticator is enabled. On success
// it stores the authenticated principal in the Gin context under "principal".
func Auth(a *auth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.Enabled() {
			c.Next()
			return
		}
		principal, err := a.Authenticate(c.Request)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			response.Abort(c, http.StatusUnauthorized, "unauthorized",
				"Missing or invalid credentials. Provide an API key (X-API-Key) or a Bearer token.")
			return
		}
		c.Set("principal", principal)
		c.Next()
	}
}
