package service

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/twmb/murmur3"
)

// ProbeEntry is the result of probing a single host.
type ProbeEntry struct {
	Input       string   `json:"input"`
	URL         string   `json:"url,omitempty"`
	Alive       bool     `json:"alive"`
	StatusCode  int      `json:"status_code,omitempty"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	ContentLen  int      `json:"content_length,omitempty"`
	Tech        []string `json:"technologies,omitempty"`
	FaviconHash int32    `json:"favicon_hash,omitempty"` // Shodan-compatible mmh3
	Error       string   `json:"error,omitempty"`
}

// ProbeResult aggregates a batch probe.
type ProbeResult struct {
	Probed     int          `json:"probed"`
	AliveCount int          `json:"alive_count"`
	Results    []ProbeEntry `json:"results"`
}

var iconHrefRe = regexp.MustCompile(`(?is)<link[^>]+rel=["']?[^"'>]*icon[^"'>]*["']?[^>]*>`)
var hrefRe = regexp.MustCompile(`(?is)href=["']?([^"'>\s]+)`)

const maxProbeTargets = 100

// ProbeHosts probes a batch of hosts for liveness, metadata, and favicon hash.
// guardFn (may be nil) enforces target-safety per host.
func ProbeHosts(ctx context.Context, targets []string, timeout time.Duration, concurrency int, guardFn func(string) error) ProbeResult {
	if concurrency <= 0 {
		concurrency = 20
	}
	// Deduplicate and cap.
	seen := make(map[string]struct{})
	uniq := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		uniq = append(uniq, t)
		if len(uniq) >= maxProbeTargets {
			break
		}
	}

	client := newHTTPClient(timeout)
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]ProbeEntry, 0, len(uniq))

	for _, target := range uniq {
		wg.Add(1)
		sem <- struct{}{}
		go func(input string) {
			defer wg.Done()
			defer func() { <-sem }()
			entry := probeOne(ctx, client, input, guardFn)
			mu.Lock()
			results = append(results, entry)
			mu.Unlock()
		}(target)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Input < results[j].Input })
	alive := 0
	for _, r := range results {
		if r.Alive {
			alive++
		}
	}
	return ProbeResult{Probed: len(results), AliveCount: alive, Results: results}
}

func probeOne(ctx context.Context, client *http.Client, input string, guardFn func(string) error) ProbeEntry {
	entry := ProbeEntry{Input: input}

	u, err := ParseURL(input)
	if err != nil {
		entry.Error = "invalid target"
		return entry
	}
	if guardFn != nil {
		if err := guardFn(u.Hostname()); err != nil {
			entry.Error = err.Error()
			return entry
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		entry.Error = "unreachable"
		return entry
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))

	entry.Alive = true
	entry.URL = resp.Request.URL.String()
	entry.StatusCode = resp.StatusCode
	entry.Server = resp.Header.Get("Server")
	entry.ContentLen = len(body)
	entry.Title = extractTitle(body)
	entry.Tech = matchTechnologies(resp.Header, body)
	entry.FaviconHash = fetchFaviconHash(ctx, client, resp.Request.URL.Scheme+"://"+resp.Request.URL.Host, body)
	return entry
}

// fetchFaviconHash locates the favicon (from a <link rel=icon> or /favicon.ico)
// and returns its Shodan-compatible mmh3 hash, or 0 if unavailable.
func fetchFaviconHash(ctx context.Context, client *http.Client, base string, body []byte) int32 {
	icon := base + "/favicon.ico"
	if m := iconHrefRe.FindSubmatch(body); m != nil {
		if hm := hrefRe.FindSubmatch(m[0]); hm != nil {
			href := strings.TrimSpace(string(hm[1]))
			switch {
			case strings.HasPrefix(href, "http://"), strings.HasPrefix(href, "https://"):
				icon = href
			case strings.HasPrefix(href, "//"):
				icon = "https:" + href
			case strings.HasPrefix(href, "/"):
				icon = base + href
			default:
				icon = base + "/" + href
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, icon, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(data) == 0 {
		return 0
	}
	return faviconHash(data)
}

// faviconHash reproduces Shodan's http.favicon.hash: mmh3 (x86 32-bit) of the
// base64-encoded icon, chunked into 76-char lines like Python base64.encodebytes.
func faviconHash(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3.Sum32([]byte(b.String())))
}
