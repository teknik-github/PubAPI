package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/store"
)

// AdminHandler serves admin-only visibility endpoints.
type AdminHandler struct {
	store *store.Store
}

// NewAdminHandler builds the admin handler.
func NewAdminHandler(st *store.Store) *AdminHandler {
	return &AdminHandler{store: st}
}

// Users handles GET /api/v1/admin/users — all accounts with key counts.
func (h *AdminHandler) Users(c *gin.Context) {
	users, err := h.store.ListUsers()
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to list users.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"users": users})
}

// Logs handles GET /api/v1/admin/logs?limit=&offset=&principal= — request logs.
func (h *AdminHandler) Logs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}
	principal := c.Query("principal")
	logs, err := h.store.ListLogs(limit, offset, principal)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to list logs.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"logs": logs, "count": len(logs), "offset": offset})
}

// DeleteUser handles DELETE /api/v1/admin/users/:id — remove a user (and their
// keys). The user is locked out immediately since sessions verify existence.
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Invalid user id.")
		return
	}
	if id == userID(c) {
		response.Fail(c, http.StatusBadRequest, "cannot_delete_self", "You cannot delete your own account.")
		return
	}
	if err := h.store.DeleteUser(id); err != nil {
		if err == store.ErrNotFound {
			response.Fail(c, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to delete user.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"deleted": id})
}

// UserKeys handles GET /api/v1/admin/users/:id/keys — a user's API keys.
func (h *AdminHandler) UserKeys(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Invalid user id.")
		return
	}
	keys, err := h.store.ListAPIKeysByUser(id)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to list keys.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"keys": keys})
}

// RevokeKey handles DELETE /api/v1/admin/keys/:id — revoke any user's key.
func (h *AdminHandler) RevokeKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Invalid key id.")
		return
	}
	if err := h.store.AdminRevokeAPIKey(id); err != nil {
		if err == store.ErrNotFound {
			response.Fail(c, http.StatusNotFound, "not_found", "Key not found.")
			return
		}
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to revoke key.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{"revoked": id})
}

// Stats handles GET /api/v1/admin/stats — aggregate usage summary.
func (h *AdminHandler) Stats(c *gin.Context) {
	stats, err := h.store.Stats()
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to compute stats.")
		return
	}
	response.OK(c, http.StatusOK, stats)
}
