// Package router assembles the Gin engine, middleware, and routes.
package router

import (
	"io/fs"
	"strings"

	"github.com/gin-gonic/gin"

	"pubapi/config"
	"pubapi/internal/auth"
	"pubapi/internal/handlers"
	"pubapi/internal/middleware"
	"pubapi/internal/store"
)

// New builds the fully-wired Gin engine. web carries the embedded static site;
// st is the persistence layer for users, keys, and request logs.
func New(cfg *config.Config, web fs.FS, st *store.Store) *gin.Engine {
	gin.SetMode(cfg.Mode)

	r := gin.New()
	// Client-IP resolution for reverse proxies / tunnels. Behind Cloudflare
	// Tunnel the peer is the tunnel (e.g. 172.x docker gateway), so read the
	// real visitor IP from the platform header instead.
	if len(cfg.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(cfg.TrustedProxies)
	}
	switch strings.ToLower(cfg.TrustedPlatform) {
	case "cloudflare", "cf":
		r.TrustedPlatform = gin.PlatformCloudflare // CF-Connecting-IP
	case "fly", "flyio":
		r.TrustedPlatform = gin.PlatformFlyIO
	case "google", "gae", "appengine":
		r.TrustedPlatform = gin.PlatformGoogleAppEngine
	case "":
		// no platform header — rely on trusted proxies / direct peer
	default:
		r.TrustedPlatform = cfg.TrustedPlatform // treat as a custom header name
	}

	r.Use(gin.Logger())
	r.Use(middleware.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS())
	r.Use(middleware.Timeout(cfg.DialTimeout * 20)) // generous per-request ceiling
	r.Use(middleware.RateLimit(cfg.RateLimitRPS, cfg.RateLimitBurst))

	h := handlers.New(cfg, web)
	authn := auth.NewService(st, cfg.JWTSecret, cfg.JWTTTL, cfg.AuthEnabled)
	acct := handlers.NewAccountHandler(st, authn)
	admin := handlers.NewAdminHandler(st)
	reqLog := middleware.NewRequestLogger(st)

	// Static site & meta
	r.GET("/", h.Index)
	r.GET("/docs", h.Docs)
	r.GET("/dashboard", h.Dashboard)
	r.GET("/tos", h.TOS)
	r.GET("/api", h.Catalog)
	r.GET("/health", h.Health)
	r.NoRoute(h.NotFound)

	// Every /api/v1 request is logged for admin visibility.
	v1 := r.Group("/api/v1")
	v1.Use(reqLog.Middleware())

	// Public auth endpoints — protected by a stricter per-IP limiter to blunt
	// credential brute-force and mass account creation.
	authGrp := v1.Group("")
	authGrp.Use(middleware.RateLimit(cfg.AuthRateRPS, cfg.AuthRateBurst))
	{
		authGrp.POST("/auth/register", acct.Register)
		authGrp.POST("/auth/login", acct.Login)
	}

	// Session-authenticated account & key management.
	account := v1.Group("")
	account.Use(middleware.RequireUser(authn))
	{
		account.GET("/account", acct.Account)
		account.POST("/keys", acct.CreateKey)
		account.GET("/keys", acct.ListKeys)
		account.DELETE("/keys/:id", acct.RevokeKey)
	}

	// Admin-only visibility.
	adminGrp := v1.Group("/admin")
	adminGrp.Use(middleware.RequireAdmin(authn))
	{
		adminGrp.GET("/users", admin.Users)
		adminGrp.DELETE("/users/:id", admin.DeleteUser)
		adminGrp.GET("/users/:id/keys", admin.UserKeys)
		adminGrp.DELETE("/keys/:id", admin.RevokeKey)
		adminGrp.GET("/logs", admin.Logs)
		adminGrp.GET("/stats", admin.Stats)
	}

	// The recon/scan/web/util API surface — guarded by API key/JWT when enabled.
	api := v1.Group("")
	api.Use(middleware.APIAuth(authn))
	{
		recon := api.Group("/recon")
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
		scan := api.Group("/scan")
		{
			scan.POST("/ports", h.PortScan)
			scan.GET("/banner", h.Banner)
		}
		web := api.Group("/web")
		{
			web.GET("/headers", h.Headers)
			web.GET("/tech", h.Tech)
			web.GET("/tls", h.TLS)
			web.GET("/surface", h.Surface)
			web.POST("/probe", h.Probe)
		}
		util := api.Group("/util")
		{
			util.POST("/hash", h.HashText)
			util.POST("/hash-identify", h.IdentifyHash)
			util.POST("/encode", h.Transform)
			util.POST("/jwt-decode", h.DecodeJWT)
		}
	}

	return r
}
