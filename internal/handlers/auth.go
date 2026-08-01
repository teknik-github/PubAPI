package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/response"
)

// AuthHandler issues JWTs in exchange for a valid API key.
type AuthHandler struct {
	auth *auth.Authenticator
}

// NewAuthHandler builds the token-issuance handler.
func NewAuthHandler(a *auth.Authenticator) *AuthHandler {
	return &AuthHandler{auth: a}
}

type tokenRequest struct {
	APIKey string `json:"api_key"`
}

// Token handles POST /api/v1/auth/token — exchange an API key for a JWT.
func (h *AuthHandler) Token(c *gin.Context) {
	if !h.auth.Enabled() {
		response.Fail(c, http.StatusNotFound, "auth_disabled", "Authentication is not enabled on this server.")
		return
	}
	var req tokenRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.APIKey == "" {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with an 'api_key' field.")
		return
	}
	if !h.auth.ValidKey(req.APIKey) {
		response.Fail(c, http.StatusUnauthorized, "invalid_api_key", "The provided API key is not valid.")
		return
	}
	token, exp, err := h.auth.Issue("api-client")
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to issue token.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{
		"token":      token,
		"token_type": "Bearer",
		"expires_at": exp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		"expires_in": int(h.auth.TTL().Seconds()),
	})
}
