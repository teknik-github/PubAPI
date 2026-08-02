package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/response"
)

// Context keys for values set by the auth middleware.
const (
	CtxPrincipal = "principal"
	CtxUserID    = "user_id"
	CtxRole      = "role"
	CtxEmail     = "email"
)

// APIAuth guards the recon/scan/web/util API surface. When API auth is enabled
// a valid API key or JWT is required; otherwise the request passes through and
// is attributed to any credential supplied (for logging) or "anon".
func APIAuth(a *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := a.AuthenticateAPI(c.Request)
		if a.APIAuthEnabled() {
			if err != nil {
				c.Header("WWW-Authenticate", "Bearer")
				response.Abort(c, http.StatusUnauthorized, "unauthorized",
					"Missing or invalid credentials. Provide an API key (X-API-Key) or Bearer token.")
				return
			}
			c.Set(CtxPrincipal, principal)
		} else if err == nil {
			c.Set(CtxPrincipal, principal)
		}
		c.Next()
	}
}

// RequireUser requires a valid session JWT and stores the user's identity.
func RequireUser(a *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := a.UserFromRequest(c.Request)
		if err != nil {
			response.Abort(c, http.StatusUnauthorized, "unauthorized", "Login required.")
			return
		}
		c.Set(CtxUserID, claims.Subject)
		c.Set(CtxRole, claims.Role)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxPrincipal, "user:"+claims.Subject)
		c.Next()
	}
}

// RequireAdmin requires a valid session JWT with the admin role.
func RequireAdmin(a *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := a.UserFromRequest(c.Request)
		if err != nil {
			response.Abort(c, http.StatusUnauthorized, "unauthorized", "Login required.")
			return
		}
		if claims.Role != "admin" {
			response.Abort(c, http.StatusForbidden, "forbidden", "Admin access required.")
			return
		}
		c.Set(CtxUserID, claims.Subject)
		c.Set(CtxRole, claims.Role)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxPrincipal, "user:"+claims.Subject)
		c.Next()
	}
}
