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

// Stats handles GET /api/v1/admin/stats — aggregate usage summary.
func (h *AdminHandler) Stats(c *gin.Context) {
	stats, err := h.store.Stats()
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to compute stats.")
		return
	}
	response.OK(c, http.StatusOK, stats)
}
