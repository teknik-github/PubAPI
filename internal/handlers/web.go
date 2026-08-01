package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/service"
)

// Headers handles GET /api/v1/web/headers?url=https://example.com
func (h *Handler) Headers(c *gin.Context) {
	u, err := service.ParseURL(c.Query("url"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?url= parameter.")
		return
	}
	if err := h.guard.CheckHost(u.Hostname()); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	audit, err := service.AuditHeaders(c.Request.Context(), u.String(), h.cfg.DialTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "fetch_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, audit)
}

// Tech handles GET /api/v1/web/tech?url=https://example.com
func (h *Handler) Tech(c *gin.Context) {
	u, err := service.ParseURL(c.Query("url"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?url= parameter.")
		return
	}
	if err := h.guard.CheckHost(u.Hostname()); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	tech, err := service.Fingerprint(c.Request.Context(), u.String(), h.cfg.DialTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "fetch_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, tech)
}

// probeRequest is the JSON body for POST /api/v1/web/probe.
type probeRequest struct {
	Hosts []string `json:"hosts"`
}

// Probe handles POST /api/v1/web/probe
func (h *Handler) Probe(c *gin.Context) {
	var req probeRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Hosts) == 0 {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with a non-empty 'hosts' array.")
		return
	}
	res := service.ProbeHosts(c.Request.Context(), req.Hosts,
		h.cfg.DialTimeout, h.cfg.ScanConcurrency, h.guard.CheckHost)
	response.OK(c, http.StatusOK, res)
}

// Surface handles GET /api/v1/web/surface?url=https://example.com
func (h *Handler) Surface(c *gin.Context) {
	u, err := service.ParseURL(c.Query("url"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?url= parameter.")
		return
	}
	if err := h.guard.CheckHost(u.Hostname()); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	res, err := service.InspectSurface(c.Request.Context(), u.String(), h.cfg.DialTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "fetch_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}

// TLS handles GET /api/v1/web/tls?host=example.com&port=443
func (h *Handler) TLS(c *gin.Context) {
	host, err := service.ValidateHost(c.Query("host"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?host= parameter.")
		return
	}
	if err := h.guard.CheckHost(host); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	port := 443
	if p := c.Query("port"); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			response.Fail(c, http.StatusBadRequest, "invalid_input", "?port= must be 1-65535.")
			return
		}
		port = n
	}
	info, err := service.InspectTLS(c.Request.Context(), host, port, h.cfg.DialTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "tls_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, info)
}
