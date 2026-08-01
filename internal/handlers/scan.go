package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/service"
)

// scanRequest is the JSON body for POST /api/v1/scan/ports.
type scanRequest struct {
	Host   string `json:"host"`
	Ports  string `json:"ports"`  // e.g. "22,80,443,8000-8100"; empty = top ports
	Banner bool   `json:"banner"` // attempt banner grabbing on open ports
}

// PortScan handles POST /api/v1/scan/ports
func (h *Handler) PortScan(c *gin.Context) {
	var req scanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with a 'host' field.")
		return
	}
	host, err := service.ValidateHost(req.Host)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid 'host'.")
		return
	}
	if err := h.guard.CheckHost(host); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}

	var ports []int
	if req.Ports == "" {
		ports = service.TopPorts()
	} else {
		ports, err = service.ParsePortSpec(req.Ports, h.cfg.MaxScanPorts)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, "invalid_input", err.Error())
			return
		}
	}

	res := service.ScanPorts(c.Request.Context(), host, ports,
		h.cfg.DialTimeout, h.cfg.ScanConcurrency, req.Banner)
	response.OK(c, http.StatusOK, res)
}

// Banner handles GET /api/v1/scan/banner?host=&port=
func (h *Handler) Banner(c *gin.Context) {
	host, err := service.ValidateHost(c.Query("host"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?host= parameter.")
		return
	}
	if err := h.guard.CheckHost(host); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	ports, err := service.ParsePortSpec(c.Query("port"), 1)
	if err != nil || len(ports) != 1 {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a single valid ?port= parameter.")
		return
	}
	res := service.ScanPorts(c.Request.Context(), host, ports,
		h.cfg.DialTimeout, 1, true)
	response.OK(c, http.StatusOK, res)
}
