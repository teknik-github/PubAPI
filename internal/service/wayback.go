package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// WaybackResult holds historical URLs discovered from the Wayback Machine.
type WaybackResult struct {
	Domain string   `json:"domain"`
	Count  int      `json:"count"`
	URLs   []string `json:"urls"`
}

// WaybackURLs queries the Internet Archive CDX API for historical URLs seen
// under a domain (including subdomains), deduplicated and capped by limit.
func WaybackURLs(ctx context.Context, domain string, limit int, timeout time.Duration) (*WaybackResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	ckey := "wb:" + domain + ":" + strconv.Itoa(limit)
	if v, ok := cacheGet[*WaybackResult](ckey); ok {
		return v, nil
	}
	endpoint := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(domain) +
		"&matchType=domain&output=json&fl=original&collapse=urlkey&limit=" + strconv.Itoa(limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := newHTTPClient(timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // cap at 32 MB
	if err != nil {
		return nil, err
	}

	// The CDX JSON is an array of arrays; the first row is a header.
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return &WaybackResult{Domain: domain, URLs: []string{}}, nil
	}

	seen := make(map[string]struct{})
	urls := make([]string, 0, len(rows))
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header row
			continue
		}
		u := row[0]
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}
	sort.Strings(urls)
	res := &WaybackResult{Domain: domain, Count: len(urls), URLs: urls}
	cacheSet(ckey, res, ttlWayback)
	return res, nil
}
