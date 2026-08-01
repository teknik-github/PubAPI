// Package router assembles the Gin engine, middleware, and routes.
package router

import (
	"io/fs"

	"github.com/gin-gonic/gin"

	"pubapi/config"
	"pubapi/internal/auth"
	"pubapi/internal/handlers"
	"pubapi/internal/middleware"
)

// New builds the fully-wired Gin engine. web carries the embedded static site.
func New(cfg *config.Config, web fs.FS) *gin.Engine {
	gin.SetMode(cfg.Mode)

	r := gin.New()
	// Gin trusts all proxies by default; restrict unless configured otherwise.
	_ = r.SetTrustedProxies(cfg.TrustedProxies)

	r.Use(gin.Logger())
	r.Use(middleware.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS())
	r.Use(middleware.Timeout(cfg.DialTimeout * 20)) // generous per-request ceiling
	r.Use(middleware.RateLimit(cfg.RateLimitRPS, cfg.RateLimitBurst))

	h := handlers.New(cfg, web)
	authn := auth.New(cfg.AuthEnabled, cfg.APIKeys, cfg.JWTSecret, cfg.JWTTTL)
	authH := handlers.NewAuthHandler(authn)

	// Static site
	r.GET("/", h.Index)
	r.GET("/docs", h.Docs)
	// Machine-readable endpoint catalog
	r.GET("/api", h.Catalog)
	r.GET("/health", h.Health)
	r.NoRoute(h.NotFound)

	v1 := r.Group("/api/v1")
	// Token issuance is public so clients can obtain a JWT from an API key.
	v1.POST("/auth/token", authH.Token)

	// Everything else requires authentication when auth is enabled.
	protected := v1.Group("")
	protected.Use(middleware.Auth(authn))
	{
		recon := protected.Group("/recon")
		{
			recon.GET("/dns", h.DNS)
			recon.GET("/subdomain", h.Subdomain)
			recon.GET("/whois", h.Whois)
			recon.GET("/reverse-ip", h.ReverseIP)
			recon.GET("/email-security", h.EmailSecurity)
			recon.GET("/takeover", h.Takeover)
			recon.GET("/profile", h.Profile)
			recon.GET("/ip", h.IPInfo)
			recon.GET("/wayback", h.Wayback)
		}
		scan := protected.Group("/scan")
		{
			scan.POST("/ports", h.PortScan)
			scan.GET("/banner", h.Banner)
		}
		web := protected.Group("/web")
		{
			web.GET("/headers", h.Headers)
			web.GET("/tech", h.Tech)
			web.GET("/tls", h.TLS)
			web.GET("/surface", h.Surface)
			web.POST("/probe", h.Probe)
		}
		util := protected.Group("/util")
		{
			util.POST("/hash", h.HashText)
			util.POST("/hash-identify", h.IdentifyHash)
			util.POST("/encode", h.Transform)
			util.POST("/jwt-decode", h.DecodeJWT)
		}
	}

	return r
}
