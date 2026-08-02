package handlers

import (
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/service"
)

// Health handles GET /health for liveness checks.
func (h *Handler) Health(c *gin.Context) {
	hits, misses, size := service.CacheStats()
	response.OK(c, http.StatusOK, gin.H{
		"status":       "ok",
		"auth_enabled": h.cfg.AuthEnabled,
		"cache": gin.H{
			"enabled": h.cfg.CacheEnabled,
			"entries": size,
			"hits":    hits,
			"misses":  misses,
		},
	})
}

// Index handles GET / and serves the static landing page.
func (h *Handler) Index(c *gin.Context) {
	h.serveHTML(c, "web/index.html")
}

// Docs handles GET /docs and serves the static documentation page.
func (h *Handler) Docs(c *gin.Context) {
	h.serveHTML(c, "web/docs.html")
}

// Dashboard handles GET /dashboard and serves the account/admin dashboard.
func (h *Handler) Dashboard(c *gin.Context) {
	h.serveHTML(c, "web/dashboard.html")
}

// TOS handles GET /tos and serves the Terms of Service page.
func (h *Handler) TOS(c *gin.Context) {
	h.serveHTML(c, "web/tos.html")
}

// serveHTML writes an embedded HTML asset with the correct content type.
func (h *Handler) serveHTML(c *gin.Context, name string) {
	b, err := fs.ReadFile(h.web, name)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Page unavailable.")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", b)
}

// Catalog handles GET /api and returns a machine-readable endpoint catalog.
func (h *Handler) Catalog(c *gin.Context) {
	response.OK(c, http.StatusOK, gin.H{
		"name":        "PubAPI OffSec",
		"version":     "1.0.0",
		"description": "Public API for offensive-security reconnaissance and utilities.",
		"disclaimer":  "For authorized security testing and research only. You are responsible for how you use it.",
		"auth": gin.H{
			"api_auth_enabled": h.cfg.AuthEnabled,
			"how":              "Register/login for a session JWT, create an API key in the dashboard, then send X-API-Key or Authorization: Bearer <api-key|jwt> on API calls.",
			"dashboard":        "GET /dashboard",
			"terms":            "GET /tos",
		},
		"endpoints": gin.H{
			"account": []gin.H{
				{"method": "POST", "path": "/api/v1/auth/register", "body": "{email, password, accept_tos}"},
				{"method": "POST", "path": "/api/v1/auth/login", "body": "{email, password}"},
				{"method": "GET", "path": "/api/v1/account", "auth": "jwt"},
				{"method": "POST", "path": "/api/v1/keys", "auth": "jwt", "body": "{name}"},
				{"method": "GET", "path": "/api/v1/keys", "auth": "jwt"},
				{"method": "DELETE", "path": "/api/v1/keys/:id", "auth": "jwt"},
			},
			"admin": []gin.H{
				{"method": "GET", "path": "/api/v1/admin/users", "auth": "admin"},
				{"method": "GET", "path": "/api/v1/admin/logs", "auth": "admin"},
				{"method": "GET", "path": "/api/v1/admin/stats", "auth": "admin"},
			},
			"recon": []gin.H{
				{"method": "GET", "path": "/api/v1/recon/dns", "params": "domain"},
				{"method": "GET", "path": "/api/v1/recon/subdomain", "params": "domain, mode(brute|passive|both)"},
				{"method": "GET", "path": "/api/v1/recon/whois", "params": "domain, raw(optional)"},
				{"method": "GET", "path": "/api/v1/recon/reverse-ip", "params": "ip"},
				{"method": "GET", "path": "/api/v1/recon/email-security", "params": "domain, selectors(optional)"},
				{"method": "GET", "path": "/api/v1/recon/takeover", "params": "domain"},
				{"method": "GET", "path": "/api/v1/recon/profile", "params": "domain"},
				{"method": "GET", "path": "/api/v1/recon/ip", "params": "ip"},
				{"method": "GET", "path": "/api/v1/recon/wayback", "params": "domain, limit(optional)"},
			},
			"scan": []gin.H{
				{"method": "POST", "path": "/api/v1/scan/ports", "body": "{host, ports?, banner?}"},
				{"method": "GET", "path": "/api/v1/scan/banner", "params": "host, port"},
			},
			"web": []gin.H{
				{"method": "GET", "path": "/api/v1/web/headers", "params": "url"},
				{"method": "GET", "path": "/api/v1/web/tech", "params": "url"},
				{"method": "GET", "path": "/api/v1/web/tls", "params": "host, port(optional)"},
				{"method": "GET", "path": "/api/v1/web/surface", "params": "url"},
				{"method": "POST", "path": "/api/v1/web/probe", "body": "{hosts: [...]}"},
			},
			"util": []gin.H{
				{"method": "POST", "path": "/api/v1/util/hash", "body": "{text, algo?}"},
				{"method": "POST", "path": "/api/v1/util/hash-identify", "body": "{hash}"},
				{"method": "POST", "path": "/api/v1/util/encode", "body": "{action, scheme, text}"},
				{"method": "POST", "path": "/api/v1/util/jwt-decode", "body": "{token}"},
			},
		},
	})
}

// NotFound handles unmatched routes with the standard envelope.
func (h *Handler) NotFound(c *gin.Context) {
	response.Fail(c, http.StatusNotFound, "not_found", "The requested endpoint does not exist. See GET / for the catalog.")
}
