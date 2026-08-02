# PubAPI OffSec

A public HTTP API for **offensive-security reconnaissance and utilities**, written in Go with the [Gin](https://github.com/gin-gonic/gin) framework.

> ⚠️ **Authorized use only.** This tool performs active reconnaissance (DNS enumeration, port scanning, banner grabbing, TLS/HTTP inspection) against the targets you supply. Only use it against systems you own or have explicit, written permission to test. You are responsible for your use.

## Features

| Module | Endpoint | What it does |
|--------|----------|--------------|
| **Recon** | `GET /api/v1/recon/dns` | Resolve A/AAAA/CNAME/MX/NS/TXT records |
| | `GET /api/v1/recon/subdomain` | Subdomain enumeration — brute-force + passive (crt.sh CT logs) |
| | `GET /api/v1/recon/whois` | WHOIS lookup (structured + optional raw) |
| | `GET /api/v1/recon/reverse-ip` | Reverse DNS (PTR) lookup |
| | `GET /api/v1/recon/email-security` | SPF / DKIM / DMARC / DNSSEC posture + grade |
| | `GET /api/v1/recon/takeover` | Subdomain takeover detection (CNAME fingerprinting) |
| | `GET /api/v1/recon/profile` | Aggregate domain recon report (runs all modules) |
| | `GET /api/v1/recon/ip` | GeoIP + ASN + reverse DNS for an IP |
| | `GET /api/v1/recon/wayback` | Historical URLs from the Wayback Machine |
| **Scan** | `POST /api/v1/scan/ports` | Concurrent TCP port scan + optional banner grab |
| | `GET /api/v1/scan/banner` | Grab a service banner from a single host:port |
| **Web** | `GET /api/v1/web/headers` | Audit & grade HTTP security headers |
| | `GET /api/v1/web/tech` | Fingerprint web technologies |
| | `GET /api/v1/web/tls` | Inspect TLS certificate & cipher |
| | `GET /api/v1/web/surface` | robots/sitemap/security.txt, HTTP methods, CORS check |
| | `POST /api/v1/web/probe` | Batch host liveness + favicon hash (Shodan-compatible mmh3) |
| **Accounts** | `POST /api/v1/auth/register` · `/auth/login` | Sign up / log in → session JWT |
| | `GET /api/v1/account` | Current user (JWT) |
| | `POST/GET /api/v1/keys` · `DELETE /keys/:id` | Client-managed API keys (JWT) |
| **Admin** | `GET /api/v1/admin/users` · `/logs` · `/stats` | Users, request logs, usage stats (admin) |
| **Web UI** | `GET /dashboard` · `GET /tos` | Account/admin dashboard · Terms of Service |
| **Util** | `POST /api/v1/util/hash` | Compute MD5/SHA1/SHA256/SHA512/CRC32 |
| | `POST /api/v1/util/hash-identify` | Guess a hash's algorithm from its shape |
| | `POST /api/v1/util/encode` | Encode/decode base64, base64url, base32, hex, url |
| | `POST /api/v1/util/jwt-decode` | Decode a JWT header/payload (no signature verify) |
| **Web UI** | `GET /` | Landing page · `GET /docs` full documentation |
| **Meta** | `GET /api` | Endpoint catalog (JSON) · `GET /health` liveness |

The landing page and documentation are embedded into the binary (`go:embed`), so a single `pubapi` binary serves both the API and its web UI — no external files needed, even in a `scratch`/distroless image.

## Quick start

```bash
# Requires Go 1.26+
go mod download
go run .              # listens on :8080

# or with the Makefile
make run
make test
make build           # -> bin/pubapi
```

### Docker

```bash
make docker
docker run -p 8080:8080 pubapi-offsec:latest
```

## Configuration

All settings are environment variables (see `.env.example`). Defaults are safe for a public deployment.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Listen port |
| `GIN_MODE` | `release` | `release` or `debug` |
| `RATE_LIMIT_RPS` | `5` | Per-IP requests/second |
| `RATE_LIMIT_BURST` | `10` | Per-IP burst allowance |
| `DIAL_TIMEOUT_MS` | `3000` | Network dial timeout |
| `MAX_SCAN_PORTS` | `1024` | Max ports per scan request |
| `SCAN_CONCURRENCY` | `100` | Parallel workers for scans |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow private/loopback/link-local targets |
| `CACHE_ENABLED` | `true` | Cache slow external lookups (per-type TTL) |
| `DB_PATH` | `pubapi.db` | SQLite file (accounts, keys, request logs) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | — | Bootstrap admin account, created on first run |
| `AUTH_ENABLED` | `false` | Require API key / JWT on the recon/scan API surface |
| `JWT_SECRET` | — | HMAC secret for signing session JWTs |
| `JWT_TTL_MINUTES` | `60` | Session-token lifetime |
| `AUTH_RATE_RPS` / `AUTH_RATE_BURST` | `0.1` / `5` | Stricter per-IP limit on login/register |

**`ALLOW_PRIVATE_TARGETS`** defaults to `false`: by design the API refuses to reach private, loopback, link-local, or cloud-metadata (`169.254.169.254`) addresses. This prevents a public, unauthenticated endpoint from being abused to scan your internal network (SSRF). Enable it only for isolated, authorized internal testing.

## Response format

Every response uses one envelope:

```json
{
  "success": true,
  "data": { "...": "..." },
  "timestamp": "2026-08-01T21:53:00Z"
}
```

Errors:

```json
{
  "success": false,
  "error": { "code": "invalid_input", "message": "Provide a valid ?domain= parameter." },
  "timestamp": "2026-08-01T21:53:00Z"
}
```

## Examples

```bash
# DNS records
curl "http://localhost:8080/api/v1/recon/dns?domain=example.com"

# Subdomain enumeration (brute-force + passive crt.sh; mode=brute|passive|both)
curl "http://localhost:8080/api/v1/recon/subdomain?domain=example.com&mode=both"

# Email spoofing posture (SPF/DKIM/DMARC/DNSSEC); custom DKIM selectors optional
curl "http://localhost:8080/api/v1/recon/email-security?domain=google.com&selectors=20230601"

# Web surface (robots, sitemap, security.txt, methods, CORS)
curl "http://localhost:8080/api/v1/web/surface?url=https://example.com"

# Subdomain takeover detection
curl "http://localhost:8080/api/v1/recon/takeover?domain=example.com"

# Aggregate domain profile (runs every recon module concurrently)
curl "http://localhost:8080/api/v1/recon/profile?domain=example.com"

# GeoIP + ASN for an IP
curl "http://localhost:8080/api/v1/recon/ip?ip=8.8.8.8"

# Historical URLs from the Wayback Machine
curl "http://localhost:8080/api/v1/recon/wayback?domain=example.com&limit=500"

# Batch host probe + favicon hash (httpx-style)
curl -X POST http://localhost:8080/api/v1/web/probe \
  -H 'Content-Type: application/json' \
  -d '{"hosts":["github.com","wordpress.org"]}'

# WHOIS
curl "http://localhost:8080/api/v1/recon/whois?domain=example.com"

# Port scan (default = common ports) with banners
curl -X POST http://localhost:8080/api/v1/scan/ports \
  -H 'Content-Type: application/json' \
  -d '{"host":"scanme.nmap.org","ports":"22,80,443,8000-8100","banner":true}'

# Security-header audit
curl "http://localhost:8080/api/v1/web/headers?url=https://example.com"

# Technology fingerprint
curl "http://localhost:8080/api/v1/web/tech?url=https://example.com"

# TLS certificate inspection
curl "http://localhost:8080/api/v1/web/tls?host=example.com&port=443"

# Hash a string (all algorithms)
curl -X POST http://localhost:8080/api/v1/util/hash \
  -H 'Content-Type: application/json' -d '{"text":"hello"}'

# Identify a hash
curl -X POST http://localhost:8080/api/v1/util/hash-identify \
  -H 'Content-Type: application/json' -d '{"hash":"5d41402abc4b2a76b9719d911017c592"}'

# Encode/decode
curl -X POST http://localhost:8080/api/v1/util/encode \
  -H 'Content-Type: application/json' \
  -d '{"action":"encode","scheme":"base64","text":"admin:admin"}'

# Decode a JWT (inspection only)
curl -X POST http://localhost:8080/api/v1/util/jwt-decode \
  -H 'Content-Type: application/json' -d '{"token":"<jwt>"}'
```

## Project layout

```
.
├── main.go                  # entrypoint + graceful shutdown
├── assets.go                # go:embed of the web/ static site
├── web/                     # landing page (index.html) + docs (docs.html)
├── config/                  # env-driven configuration
├── internal/
│   ├── router/              # Gin engine + route wiring
│   ├── middleware/          # rate limit, CORS, recovery, security headers
│   ├── handlers/            # HTTP handlers per module
│   ├── service/             # recon / scan / web / util logic + validation
│   └── response/            # uniform JSON envelope
├── Dockerfile
├── Makefile
└── .env.example
```

## Accounts, API keys & admin

Accounts, API keys, and request logs are persisted in **SQLite** (`DB_PATH`). Manage everything from the **dashboard** at `/dashboard`; Terms of Service at `/tos`.

**Flow:** register/login → session JWT → create an API key → call the API with the key.

```bash
# create the first admin (once)
ADMIN_EMAIL=admin@you.com ADMIN_PASSWORD=change-me AUTH_ENABLED=true JWT_SECRET=long-secret go run .

# a client registers and logs in → session JWT
JWT=$(curl -s -X POST localhost:8080/api/v1/auth/register \
  -d '{"email":"me@corp.com","password":"secret123","accept_tos":true}' | jq -r .data.token)

# create an API key (shown once)
KEY=$(curl -s -X POST localhost:8080/api/v1/keys -H "Authorization: Bearer $JWT" \
  -d '{"name":"laptop"}' | jq -r .data.key)

# call the API with the key
curl "localhost:8080/api/v1/recon/dns?domain=example.com" -H "X-API-Key: $KEY"
```

- **Passwords** hashed with bcrypt; **API keys** stored as SHA-256 hashes (plaintext shown once).
- **Sessions** are HS256 JWTs (`JWT_SECRET`, `JWT_TTL_MINUTES`); `login`/`register` carry a stricter rate limit to blunt brute-force.
- **Admin** (`ADMIN_EMAIL`) can view users, request logs, and usage stats via `/api/v1/admin/*` and the dashboard — so you can see who is using the API.
- **Request logging:** every `/api/v1/*` call is recorded (time, method, path, status, IP, principal, latency).
- `AUTH_ENABLED` controls only whether the recon/scan API requires a key; accounts/dashboard/logging work regardless.

## Security & safety notes

- **Accounts + API keys + optional enforcement** (above); with `AUTH_ENABLED=false` the recon API is open but all usage is still logged. Enable auth or put it behind a gateway before exposing broadly.
- SSRF guard blocks non-public targets by default (`ALLOW_PRIVATE_TARGETS`).
- Input validation on every domain/host/URL/IP parameter.
- Port count, response body size, and banner length are all capped.
- Graceful shutdown on SIGINT/SIGTERM.

## License

Provided as-is for authorized security testing and education.
