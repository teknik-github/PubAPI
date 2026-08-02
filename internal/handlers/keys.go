package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/response"
	"pubapi/internal/store"
)

type createKeyRequest struct {
	Name string `json:"name"`
}

// CreateKey handles POST /api/v1/keys — mint a new API key for the caller.
// The plaintext key is returned exactly once.
func (h *AccountHandler) CreateKey(c *gin.Context) {
	var req createKeyRequest
	_ = c.ShouldBindJSON(&req)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "default"
	}
	if len(name) > 60 {
		name = name[:60]
	}

	plaintext, prefix, keyHash := auth.GenerateAPIKey()
	key, err := h.store.CreateAPIKey(userID(c), name, prefix, keyHash)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to create API key.")
		return
	}
	response.OK(c, http.StatusCreated, gin.H{
		"id":         key.ID,
		"name":       key.Name,
		"key":        plaintext, // shown once — store it now
		"prefix":     prefix,
		"created_at": key.CreatedAt,
		"note":       "Store this key now — it will not be shown again.",
	})
}

// ListKeys handles GET /api/v1/keys — the caller's keys (never the plaintext).
func (h *AccountHandler) ListKeys(c *gin.Context) {
	keys, err := h.store.ListAPIKeysByUser(userID(c))
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to list keys.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"keys": keys})
}

// RevokeKey handles DELETE /api/v1/keys/:id — revoke one of the caller's keys.
func (h *AccountHandler) RevokeKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Invalid key id.")
		return
	}
	if err := h.store.RevokeAPIKey(id, userID(c)); err != nil {
		if err == store.ErrNotFound {
			response.Fail(c, http.StatusNotFound, "not_found", "Key not found.")
			return
		}
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to revoke key.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"revoked": id})
}
