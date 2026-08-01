package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubEntry is a merged subdomain finding across enumeration sources.
type SubEntry struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
	Sources   []string `json:"sources"` // "brute" and/or "passive"
	Resolved  bool     `json:"resolved"`
}

// SubEnumResult is the response for a subdomain enumeration run.
type SubEnumResult struct {
	Domain       string     `json:"domain"`
	Mode         string     `json:"mode"`
	BruteTested  int        `json:"brute_tested"`
	PassiveFound int        `json:"passive_found"`
	Found        int        `json:"found"`
	Subdomains   []SubEntry `json:"subdomains"`
}

// EnumerateSubdomains runs brute-force and/or passive (crt.sh) enumeration and
// merges the results, deduplicating by FQDN and unioning sources and IPs.
// mode is one of "brute", "passive", or "both".
func EnumerateSubdomains(ctx context.Context, domain, mode string, words []string, concurrency int, ctTimeout time.Duration) SubEnumResult {
	if mode == "" {
		mode = "both"
	}
	out := SubEnumResult{Domain: domain, Mode: mode}

	var mu sync.Mutex
	merged := make(map[string]*SubEntry)
	add := func(fqdn string, ips []string, source string, resolved bool) {
		mu.Lock()
		defer mu.Unlock()
		e, ok := merged[fqdn]
		if !ok {
			e = &SubEntry{Subdomain: fqdn}
			merged[fqdn] = e
		}
		if !containsStr(e.Sources, source) {
			e.Sources = append(e.Sources, source)
		}
		for _, ip := range ips {
			if !containsStr(e.IPs, ip) {
				e.IPs = append(e.IPs, ip)
			}
		}
		if resolved {
			e.Resolved = true
		}
	}

	var wg sync.WaitGroup

	if mode == "brute" || mode == "both" {
		out.BruteTested = countUsableWords(words)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, r := range SubdomainScan(ctx, domain, words, concurrency) {
				add(r.Subdomain, r.IPs, "brute", true)
			}
		}()
	}

	if mode == "passive" || mode == "both" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names := PassiveSubdomains(ctx, domain, ctTimeout)
			out.PassiveFound = len(names)
			// Resolve passive names concurrently; keep unresolved ones too,
			// since historical certs surface decommissioned but relevant hosts.
			for _, res := range resolveHosts(ctx, names, concurrency) {
				add(res.Subdomain, res.IPs, "passive", len(res.IPs) > 0)
			}
		}()
	}
	wg.Wait()

	entries := make([]SubEntry, 0, len(merged))
	for _, e := range merged {
		sort.Strings(e.IPs)
		sort.Strings(e.Sources)
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Subdomain < entries[j].Subdomain })
	out.Subdomains = entries
	out.Found = len(entries)
	return out
}

// PassiveSubdomains queries crt.sh Certificate Transparency logs and returns
// the unique subdomains observed in issued certificates for the domain.
func PassiveSubdomains(ctx context.Context, domain string, timeout time.Duration) []string {
	if v, ok := cacheGet[[]string]("ct:" + domain); ok {
		return v
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	endpoint := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := newHTTPClient(timeout).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // cap at 16 MB
	if err != nil {
		return nil
	}

	var records []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}

	set := make(map[string]struct{})
	suffix := "." + domain
	consider := func(raw string) {
		name := strings.TrimSpace(strings.ToLower(raw))
		name = strings.TrimPrefix(name, "*.") // drop wildcard prefix
		if name == "" || strings.ContainsAny(name, " \t") {
			return
		}
		if name == domain || strings.HasSuffix(name, suffix) {
			set[name] = struct{}{}
		}
	}
	for _, rec := range records {
		for _, line := range strings.Split(rec.NameValue, "\n") {
			consider(line)
		}
		consider(rec.CommonName)
	}

	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	// Only cache non-empty results so a transient crt.sh failure isn't sticky.
	if len(names) > 0 {
		cacheSet("ct:"+domain, names, ttlPassive)
	}
	return names
}

// resolveHosts resolves a list of FQDNs concurrently and returns one SubResult
// per input name (IPs empty when the name does not resolve).
func resolveHosts(ctx context.Context, fqdns []string, concurrency int) []SubResult {
	if concurrency <= 0 {
		concurrency = 50
	}
	var res net.Resolver
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]SubResult, 0, len(fqdns))

	for _, fqdn := range fqdns {
		select {
		case <-ctx.Done():
			wg.Wait()
			return results
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, _ := res.LookupHost(ctx, name)
			mu.Lock()
			results = append(results, SubResult{Subdomain: name, IPs: ips})
			mu.Unlock()
		}(fqdn)
	}
	wg.Wait()
	return results
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func countUsableWords(words []string) int {
	n := 0
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			n++
		}
	}
	return n
}
