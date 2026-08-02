package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	Host            string
	Port            string
	Mode            string        // gin mode: debug | release
	RateLimitRPS    float64       // requests per second per client IP
	RateLimitBurst  int           // burst size per client IP
	AuthRateRPS     float64       // stricter per-IP rate for login/register
	AuthRateBurst   int           // burst for login/register
	DialTimeout     time.Duration // network dial timeout for scans/lookups
	MaxScanPorts    int           // safety cap on ports scanned per request
	ScanConcurrency int           // parallel workers for port scans
	TrustedProxies  []string      // proxies Gin should trust for client IP
	AllowPrivate    bool          // allow targeting private/loopback/link-local IPs
	CacheEnabled    bool          // cache slow external lookups (crt.sh, WHOIS, ...)

	AuthEnabled bool          // require API key / JWT on the recon/scan API surface
	JWTSecret   string        // HMAC secret for signing/verifying session JWTs
	JWTTTL      time.Duration // session-token lifetime

	DBPath        string // SQLite database file path
	AdminEmail    string // bootstrap admin account email
	AdminPassword string // bootstrap admin account password
}

// Load reads configuration from the environment, applying sane defaults.
func Load() *Config {
	return &Config{
		Host:            getEnv("HOST", "0.0.0.0"),
		Port:            getEnv("PORT", "8080"),
		Mode:            getEnv("GIN_MODE", "release"),
		RateLimitRPS:    getEnvFloat("RATE_LIMIT_RPS", 5),
		RateLimitBurst:  getEnvInt("RATE_LIMIT_BURST", 10),
		AuthRateRPS:     getEnvFloat("AUTH_RATE_RPS", 0.1), // ~6 attempts/min sustained
		AuthRateBurst:   getEnvInt("AUTH_RATE_BURST", 5),
		DialTimeout:     time.Duration(getEnvInt("DIAL_TIMEOUT_MS", 3000)) * time.Millisecond,
		MaxScanPorts:    getEnvInt("MAX_SCAN_PORTS", 1024),
		ScanConcurrency: getEnvInt("SCAN_CONCURRENCY", 100),
		TrustedProxies:  nil,
		AllowPrivate:    getEnvBool("ALLOW_PRIVATE_TARGETS", false),
		CacheEnabled:    getEnvBool("CACHE_ENABLED", true),

		AuthEnabled: getEnvBool("AUTH_ENABLED", false),
		JWTSecret:   getEnv("JWT_SECRET", ""),
		JWTTTL:      time.Duration(getEnvInt("JWT_TTL_MINUTES", 60)) * time.Minute,

		DBPath:        getEnv("DB_PATH", "pubapi.db"),
		AdminEmail:    getEnv("ADMIN_EMAIL", ""),
		AdminPassword: getEnv("ADMIN_PASSWORD", ""),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getEnvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
