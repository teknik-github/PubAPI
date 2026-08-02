package middleware

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/response"
	"pubapi/internal/store"
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

// RequireUser requires a valid session JWT for an existing user.
func RequireUser(a *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, err := a.ResolveSession(c.Request)
		if err != nil {
			response.Abort(c, http.StatusUnauthorized, "unauthorized", "Login required.")
			return
		}
		setIdentity(c, u)
		c.Next()
	}
}

// RequireAdmin requires a valid session JWT for an existing admin user.
func RequireAdmin(a *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, err := a.ResolveSession(c.Request)
		if err != nil {
			response.Abort(c, http.StatusUnauthorized, "unauthorized", "Login required.")
			return
		}
		if u.Role != "admin" {
			response.Abort(c, http.StatusForbidden, "forbidden", "Admin access required.")
			return
		}
		setIdentity(c, u)
		c.Next()
	}
}

func setIdentity(c *gin.Context, u *store.User) {
	c.Set(CtxUserID, strconv.FormatInt(u.ID, 10))
	c.Set(CtxRole, u.Role)
	c.Set(CtxEmail, u.Email)
	c.Set(CtxPrincipal, "user:"+strconv.FormatInt(u.ID, 10))
}
