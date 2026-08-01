package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// securityHeaders are the response headers we grade a site on.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"X-XSS-Protection",
}

// HeaderAudit reports which security headers a URL sets and which are missing.
type HeaderAudit struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Present    map[string]string `json:"present"`
	Missing    []string          `json:"missing"`
	Grade      string            `json:"grade"`
	Server     string            `json:"server,omitempty"`
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			// The target is user-supplied and may have a broken chain; we only
			// inspect headers/tech, so certificate validity is not required.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		},
	}
}

// AuditHeaders fetches a URL and grades its security-relevant headers.
func AuditHeaders(ctx context.Context, rawURL string, timeout time.Duration) (*HeaderAudit, error) {
	u, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := newHTTPClient(timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	audit := &HeaderAudit{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Present:    map[string]string{},
		Missing:    []string{},
		Server:     resp.Header.Get("Server"),
	}
	for _, h := range securityHeaders {
		if v := resp.Header.Get(h); v != "" {
			audit.Present[h] = v
		} else {
			audit.Missing = append(audit.Missing, h)
		}
	}
	audit.Grade = grade(len(audit.Present), len(securityHeaders))
	return audit, nil
}

func grade(present, total int) string {
	ratio := float64(present) / float64(total)
	switch {
	case ratio >= 0.85:
		return "A"
	case ratio >= 0.65:
		return "B"
	case ratio >= 0.45:
		return "C"
	case ratio >= 0.25:
		return "D"
	default:
		return "F"
	}
}

// TechResult lists technologies fingerprinted from a response.
type TechResult struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	PoweredBy    string   `json:"powered_by,omitempty"`
	Technologies []string `json:"technologies"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// techSignatures maps a technology name to substrings that betray it in the
// response body or headers.
var techSignatures = map[string][]string{
	"WordPress":        {"wp-content", "wp-includes", "/wp-json"},
	"Drupal":           {"Drupal.settings", "/sites/default/files", "X-Generator: Drupal"},
	"Joomla":           {"/media/jui/", "com_content", "/media/system/js/"},
	"React":            {"data-reactroot", "react.production.min.js", "__NEXT_DATA__"},
	"Next.js":          {"__NEXT_DATA__", "/_next/static"},
	"Vue.js":           {"data-v-", "vue.runtime", "__vue__"},
	"Angular":          {"ng-version", "ng-app", "angular.min.js"},
	"jQuery":           {"jquery.min.js", "jquery-"},
	"Bootstrap":        {"bootstrap.min.css", "bootstrap.bundle"},
	"Laravel":          {"laravel_session", "XSRF-TOKEN"},
	"Cloudflare":       {"cf-ray", "__cfduid", "Server: cloudflare"},
	"Nginx":            {"Server: nginx"},
	"Apache":           {"Server: Apache"},
	"Express":          {"X-Powered-By: Express"},
	"PHP":              {"X-Powered-By: PHP", "PHPSESSID"},
	"ASP.NET":          {"X-AspNet-Version", "ASP.NET", "__VIEWSTATE"},
	"Shopify":          {"cdn.shopify.com", "myshopify.com", "X-ShopId"},
	"Google Analytics": {"google-analytics.com", "gtag(", "ga.js"},
}

// Fingerprint fetches a URL and infers technologies from headers and body.
func Fingerprint(ctx context.Context, rawURL string, timeout time.Duration) (*TechResult, error) {
	u, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := newHTTPClient(timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10)) // cap at 512 KB

	res := &TechResult{
		URL:          resp.Request.URL.String(),
		StatusCode:   resp.StatusCode,
		Server:       resp.Header.Get("Server"),
		PoweredBy:    resp.Header.Get("X-Powered-By"),
		Technologies: matchTechnologies(resp.Header, body),
	}
	if m := titleRe.FindSubmatch(body); len(m) == 2 {
		res.Title = sanitize(strings.TrimSpace(string(m[1])))
	}
	return res, nil
}

// matchTechnologies infers technology names from response headers and body by
// scanning a combined haystack for known signatures.
func matchTechnologies(header http.Header, body []byte) []string {
	var hb strings.Builder
	for k, vals := range header {
		for _, v := range vals {
			fmt.Fprintf(&hb, "%s: %s\n", k, v)
		}
	}
	haystack := hb.String() + string(body)

	found := map[string]bool{}
	for tech, sigs := range techSignatures {
		for _, sig := range sigs {
			if strings.Contains(haystack, sig) {
				found[tech] = true
				break
			}
		}
	}
	techs := make([]string, 0, len(found))
	for t := range found {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	return techs
}

// extractTitle pulls the <title> text from an HTML body, sanitized.
func extractTitle(body []byte) string {
	if m := titleRe.FindSubmatch(body); len(m) == 2 {
		return sanitize(strings.TrimSpace(string(m[1])))
	}
	return ""
}

// TLSInfo summarizes a server's TLS certificate and negotiated parameters.
type TLSInfo struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Version         string   `json:"version"`
	CipherSuite     string   `json:"cipher_suite"`
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	SANs            []string `json:"subject_alt_names,omitempty"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	Expired         bool     `json:"expired"`
	SignatureAlgo   string   `json:"signature_algorithm"`
}

// InspectTLS connects to host:port and reports certificate details.
func InspectTLS(ctx context.Context, host string, port int, timeout time.Duration) (*TLSInfo, error) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	conn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // we report validity, not enforce it
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	cert := state.PeerCertificates[0]
	info := &TLSInfo{
		Host:          host,
		Port:          port,
		Version:       tlsVersion(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SANs:          cert.DNSNames,
		NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}
	info.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
	info.Expired = time.Now().After(cert.NotAfter)
	return info, nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

const userAgent = "PubAPI-OffSec/1.0 (+security-research)"
