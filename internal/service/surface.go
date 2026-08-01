package service

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// SurfaceResult aggregates common web-surface reconnaissance for a URL.
type SurfaceResult struct {
	URL         string      `json:"url"`
	Robots      RobotsInfo  `json:"robots"`
	Sitemap     SitemapInfo `json:"sitemap"`
	SecurityTxt SecurityTxt `json:"security_txt"`
	Methods     MethodsInfo `json:"methods"`
	CORS        CORSInfo    `json:"cors"`
	Findings    []Finding   `json:"findings"`
}

type RobotsInfo struct {
	Present  bool     `json:"present"`
	Disallow []string `json:"disallow,omitempty"`
	Sitemaps []string `json:"sitemaps,omitempty"`
}

type SitemapInfo struct {
	Present  bool `json:"present"`
	URLCount int  `json:"url_count"`
}

type SecurityTxt struct {
	Present  bool   `json:"present"`
	Location string `json:"location,omitempty"`
	Contact  string `json:"contact,omitempty"`
}

type MethodsInfo struct {
	Allowed   []string `json:"allowed,omitempty"`
	Dangerous []string `json:"dangerous,omitempty"`
}

type CORSInfo struct {
	ACAO             string `json:"access_control_allow_origin,omitempty"`
	AllowCredentials bool   `json:"allow_credentials"`
	ReflectsOrigin   bool   `json:"reflects_origin"`
	Misconfigured    bool   `json:"misconfigured"`
	Severity         string `json:"severity,omitempty"`
	Note             string `json:"note,omitempty"`
}

var (
	locRe            = regexp.MustCompile(`(?i)<loc>`)
	dangerousMethods = map[string]bool{"PUT": true, "DELETE": true, "TRACE": true, "PATCH": true, "CONNECT": true}
	corsProbeOrigin  = "https://pubapi-cors-probe.example.com"
)

// InspectSurface probes robots/sitemap/security.txt, allowed methods, and CORS.
func InspectSurface(ctx context.Context, rawURL string, timeout time.Duration) (*SurfaceResult, error) {
	u, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	base := u.Scheme + "://" + u.Host
	client := newHTTPClient(timeout)
	res := &SurfaceResult{URL: base, Findings: []Finding{}}

	var wg sync.WaitGroup
	wg.Add(5)
	go func() { defer wg.Done(); res.Robots = fetchRobots(ctx, client, base) }()
	go func() { defer wg.Done(); res.Sitemap = fetchSitemap(ctx, client, base) }()
	go func() { defer wg.Done(); res.SecurityTxt = fetchSecurityTxt(ctx, client, base) }()
	go func() { defer wg.Done(); res.Methods = fetchMethods(ctx, client, base) }()
	go func() { defer wg.Done(); res.CORS = checkCORS(ctx, client, base) }()
	wg.Wait()

	buildSurfaceFindings(res)
	return res, nil
}

func getText(ctx context.Context, client *http.Client, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return resp.StatusCode, string(body)
}

func fetchRobots(ctx context.Context, client *http.Client, base string) RobotsInfo {
	info := RobotsInfo{}
	status, body := getText(ctx, client, base+"/robots.txt")
	if status != http.StatusOK || !strings.Contains(strings.ToLower(body), "user-agent") && !strings.Contains(strings.ToLower(body), "disallow") {
		return info
	}
	info.Present = true
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "disallow:") {
			p := strings.TrimSpace(line[len("disallow:"):])
			if p != "" && !containsStr(info.Disallow, p) {
				info.Disallow = append(info.Disallow, p)
			}
		} else if strings.HasPrefix(low, "sitemap:") {
			s := strings.TrimSpace(line[len("sitemap:"):])
			if s != "" && !containsStr(info.Sitemaps, s) {
				info.Sitemaps = append(info.Sitemaps, s)
			}
		}
	}
	if len(info.Disallow) > 40 {
		info.Disallow = info.Disallow[:40]
	}
	return info
}

func fetchSitemap(ctx context.Context, client *http.Client, base string) SitemapInfo {
	info := SitemapInfo{}
	status, body := getText(ctx, client, base+"/sitemap.xml")
	if status != http.StatusOK || !strings.Contains(strings.ToLower(body), "<urlset") && !strings.Contains(strings.ToLower(body), "<sitemapindex") {
		return info
	}
	info.Present = true
	info.URLCount = len(locRe.FindAllStringIndex(body, -1))
	return info
}

func fetchSecurityTxt(ctx context.Context, client *http.Client, base string) SecurityTxt {
	info := SecurityTxt{}
	for _, loc := range []string{"/.well-known/security.txt", "/security.txt"} {
		status, body := getText(ctx, client, base+loc)
		if status == http.StatusOK && strings.Contains(strings.ToLower(body), "contact:") {
			info.Present = true
			info.Location = loc
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "contact:") {
					info.Contact = strings.TrimSpace(line[strings.Index(line, ":")+1:])
					break
				}
			}
			return info
		}
	}
	return info
}

func fetchMethods(ctx context.Context, client *http.Client, base string) MethodsInfo {
	info := MethodsInfo{}
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, base+"/", nil)
	if err != nil {
		return info
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}
	if allow == "" {
		return info
	}
	seen := map[string]bool{}
	for _, m := range strings.Split(allow, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		info.Allowed = append(info.Allowed, m)
		if dangerousMethods[m] {
			info.Dangerous = append(info.Dangerous, m)
		}
	}
	sort.Strings(info.Allowed)
	sort.Strings(info.Dangerous)
	return info
}

func checkCORS(ctx context.Context, client *http.Client, base string) CORSInfo {
	info := CORSInfo{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return info
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", corsProbeOrigin)
	resp, err := client.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	info.ACAO = acao
	info.AllowCredentials = acac
	if acao == "" {
		return info
	}
	info.ReflectsOrigin = acao == corsProbeOrigin
	switch {
	case info.ReflectsOrigin && acac:
		info.Misconfigured = true
		info.Severity = "high"
		info.Note = "Origin dipantulkan dengan Allow-Credentials: true — memungkinkan pencurian data terautentikasi lintas asal."
	case info.ReflectsOrigin:
		info.Misconfigured = true
		info.Severity = "medium"
		info.Note = "Origin arbitrer dipantulkan pada Access-Control-Allow-Origin."
	case acao == "*" && acac:
		info.Misconfigured = true
		info.Severity = "low"
		info.Note = "Wildcard dengan credentials (diabaikan browser, tetapi menandakan konfigurasi keliru)."
	}
	return info
}

func buildSurfaceFindings(r *SurfaceResult) {
	if len(r.Methods.Dangerous) > 0 {
		r.Findings = append(r.Findings, Finding{"medium", "Metode HTTP berisiko diizinkan: " + strings.Join(r.Methods.Dangerous, ", ") + "."})
	}
	if r.CORS.Misconfigured {
		r.Findings = append(r.Findings, Finding{r.CORS.Severity, "CORS misconfiguration: " + r.CORS.Note})
	}
	if r.Robots.Present && len(r.Robots.Disallow) > 0 {
		r.Findings = append(r.Findings, Finding{"info", "robots.txt mengungkap path Disallow — kadang membocorkan area sensitif."})
	}
	if !r.SecurityTxt.Present {
		r.Findings = append(r.Findings, Finding{"info", "Tidak ada security.txt (kanal pelaporan kerentanan)."})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, Finding{"info", "Tidak ada temuan permukaan yang menonjol."})
	}
}
