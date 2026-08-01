package handlers

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/service"
)

// DNS handles GET /api/v1/recon/dns?domain=example.com
func (h *Handler) DNS(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	records, err := service.LookupDNS(c.Request.Context(), domain)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, records)
}

// ReverseIP handles GET /api/v1/recon/reverse-ip?ip=1.2.3.4
func (h *Handler) ReverseIP(c *gin.Context) {
	ip := c.Query("ip")
	if net.ParseIP(ip) == nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?ip= parameter.")
		return
	}
	if err := h.guard.CheckHost(ip); err != nil {
		response.Fail(c, http.StatusForbidden, "target_blocked", err.Error())
		return
	}
	names, err := service.ReverseIP(c.Request.Context(), ip)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, gin.H{"ip": ip, "hostnames": names})
}

// Whois handles GET /api/v1/recon/whois?domain=example.com&raw=true
func (h *Handler) Whois(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	includeRaw := c.Query("raw") == "true"
	res, err := service.LookupWhois(c.Request.Context(), domain, includeRaw)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}

// Subdomain handles GET /api/v1/recon/subdomain?domain=example.com&mode=both
// mode: "brute" (built-in wordlist), "passive" (crt.sh CT logs), or "both".
func (h *Handler) Subdomain(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(c.DefaultQuery("mode", "both")))
	switch mode {
	case "brute", "passive", "both":
	default:
		response.Fail(c, http.StatusBadRequest, "invalid_input", "mode must be one of: brute, passive, both.")
		return
	}
	words := service.DefaultSubdomains()
	result := service.EnumerateSubdomains(c.Request.Context(), domain, mode, words,
		h.cfg.ScanConcurrency, h.cfg.DialTimeout*6)
	response.OK(c, http.StatusOK, result)
}

// maxCustomDKIMSelectors caps user-supplied selectors to bound DNS queries.
const maxCustomDKIMSelectors = 25

// waybackTimeout is the ceiling for the (often slow) Internet Archive CDX API.
const waybackTimeout = 45 * time.Second

// EmailSecurity handles GET /api/v1/recon/email-security?domain=example.com
// Optional ?selectors=sel1,sel2 adds custom DKIM selectors to probe.
func (h *Handler) EmailSecurity(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}

	var selectors []string
	if raw := c.Query("selectors"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			if s := strings.TrimSpace(part); s != "" {
				selectors = append(selectors, s)
			}
		}
		if len(selectors) > maxCustomDKIMSelectors {
			response.Fail(c, http.StatusBadRequest, "invalid_input",
				"Too many custom selectors (max 25).")
			return
		}
	}

	res, err := service.AnalyzeEmailSecurity(c.Request.Context(), domain, selectors)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}

// Takeover handles GET /api/v1/recon/takeover?domain=example.com
func (h *Handler) Takeover(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	ctx := c.Request.Context()
	// Build candidate set from passive (crt.sh) discovery plus the brute wordlist.
	candidates := service.PassiveSubdomains(ctx, domain, h.cfg.DialTimeout*6)
	for _, w := range service.DefaultSubdomains() {
		candidates = append(candidates, w+"."+domain)
	}
	res := service.DetectTakeovers(ctx, domain, candidates, h.cfg.ScanConcurrency, h.cfg.DialTimeout)
	response.OK(c, http.StatusOK, res)
}

// Profile handles GET /api/v1/recon/profile?domain=example.com
func (h *Handler) Profile(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	res := service.BuildDomainProfile(c.Request.Context(), domain, h.cfg.DialTimeout)
	response.OK(c, http.StatusOK, res)
}

// IPInfo handles GET /api/v1/recon/ip?ip=8.8.8.8
func (h *Handler) IPInfo(c *gin.Context) {
	ip := strings.TrimSpace(c.Query("ip"))
	if net.ParseIP(ip) == nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?ip= parameter.")
		return
	}
	res, err := service.LookupIPInfo(c.Request.Context(), ip, h.cfg.DialTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}

// Wayback handles GET /api/v1/recon/wayback?domain=example.com&limit=1000
func (h *Handler) Wayback(c *gin.Context) {
	domain, err := service.ValidateDomain(c.Query("domain"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid ?domain= parameter.")
		return
	}
	limit := 1000
	if raw := c.Query("limit"); raw != "" {
		if n, e := strconv.Atoi(raw); e == nil && n > 0 {
			limit = n
		}
	}
	// The Wayback CDX API is frequently slow; give it a generous fixed ceiling.
	res, err := service.WaybackURLs(c.Request.Context(), domain, limit, waybackTimeout)
	if err != nil {
		response.Fail(c, http.StatusBadGateway, "lookup_failed", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}
