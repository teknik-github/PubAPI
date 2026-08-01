// Package service holds the offensive-security logic behind the API handlers.
package service

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ErrPrivateTarget is returned when a request targets a non-public address
// while private targeting is disabled (the default for a public service).
var ErrPrivateTarget = errors.New("targeting private, loopback, or link-local addresses is disabled")

// ErrInvalidTarget is returned for malformed hosts, domains, or URLs.
var ErrInvalidTarget = errors.New("invalid target")

var domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// Guard centralizes target-safety checks so every module honors the same rules.
type Guard struct {
	AllowPrivate bool
}

// NewGuard builds a Guard from configuration.
func NewGuard(allowPrivate bool) *Guard {
	return &Guard{AllowPrivate: allowPrivate}
}

// ValidateDomain checks a domain is syntactically valid.
func ValidateDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || len(domain) > 253 {
		return "", ErrInvalidTarget
	}
	if !domainRe.MatchString(domain) {
		return "", fmt.Errorf("%w: not a valid domain name", ErrInvalidTarget)
	}
	return domain, nil
}

// ValidateHost accepts either a domain or an IP literal and returns it cleaned.
func ValidateHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ErrInvalidTarget
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	return ValidateDomain(host)
}

// CheckHost resolves the host and ensures every resolved address is public
// unless private targeting is explicitly allowed.
func (g *Guard) CheckHost(host string) error {
	if g.AllowPrivate {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowed(ip) {
			return ErrPrivateTarget
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// Let the caller's own lookup surface the DNS error; only block here.
		return nil
	}
	for _, ip := range ips {
		if isDisallowed(ip) {
			return ErrPrivateTarget
		}
	}
	return nil
}

// isDisallowed reports whether an IP falls into a range a public service
// should not be tricked into reaching (loopback, private, link-local,
// unspecified, and the cloud metadata address).
func isDisallowed(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Cloud instance metadata endpoint.
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

// ParseURL validates and normalizes an http(s) URL for web modules.
func ParseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidTarget
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: only http and https are supported", ErrInvalidTarget)
	}
	if u.Hostname() == "" {
		return nil, ErrInvalidTarget
	}
	return u, nil
}
