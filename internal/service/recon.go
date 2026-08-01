package service

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"

	whois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// DNSRecords groups the resolvable record types for a domain.
type DNSRecords struct {
	Domain string   `json:"domain"`
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	MX     []string `json:"mx,omitempty"`
	NS     []string `json:"ns,omitempty"`
	TXT    []string `json:"txt,omitempty"`
}

// LookupDNS resolves common record types for a domain concurrently.
func LookupDNS(ctx context.Context, domain string) (*DNSRecords, error) {
	if v, ok := cacheGet[*DNSRecords]("dns:" + domain); ok {
		return v, nil
	}
	r := &DNSRecords{Domain: domain}
	var res net.Resolver
	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		if ips, err := res.LookupIP(ctx, "ip4", domain); err == nil {
			for _, ip := range ips {
				r.A = append(r.A, ip.String())
			}
		}
	}()
	go func() {
		defer wg.Done()
		if ips, err := res.LookupIP(ctx, "ip6", domain); err == nil {
			for _, ip := range ips {
				r.AAAA = append(r.AAAA, ip.String())
			}
		}
	}()
	go func() {
		defer wg.Done()
		if cname, err := res.LookupCNAME(ctx, domain); err == nil {
			cname = strings.TrimSuffix(cname, ".")
			// LookupCNAME echoes the domain itself when no CNAME exists.
			if !strings.EqualFold(cname, domain) {
				r.CNAME = cname
			}
		}
	}()
	go func() {
		defer wg.Done()
		if mxs, err := res.LookupMX(ctx, domain); err == nil {
			for _, mx := range mxs {
				host := strings.TrimSuffix(mx.Host, ".")
				if host != "" { // skip "null MX" (RFC 7505) empty entries
					r.MX = append(r.MX, host)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		if nss, err := res.LookupNS(ctx, domain); err == nil {
			for _, ns := range nss {
				r.NS = append(r.NS, strings.TrimSuffix(ns.Host, "."))
			}
		}
	}()
	wg.Wait()

	if txts, err := res.LookupTXT(ctx, domain); err == nil {
		r.TXT = txts
	}

	sort.Strings(r.A)
	sort.Strings(r.AAAA)
	sort.Strings(r.MX)
	sort.Strings(r.NS)
	cacheSet("dns:"+domain, r, ttlDNS)
	return r, nil
}

// ReverseIP performs a reverse DNS (PTR) lookup for an IP address.
func ReverseIP(ctx context.Context, ip string) ([]string, error) {
	var res net.Resolver
	names, err := res.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	sort.Strings(names)
	return names, nil
}

// SubResult is a single discovered subdomain and its addresses.
type SubResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
}

// SubdomainScan brute-forces subdomains from a wordlist by resolving each,
// bounded by the given concurrency and the request context deadline.
func SubdomainScan(ctx context.Context, domain string, words []string, concurrency int) []SubResult {
	if concurrency <= 0 {
		concurrency = 50
	}
	var res net.Resolver
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := make([]SubResult, 0)

	for _, w := range words {
		w = strings.TrimSpace(strings.ToLower(w))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			sortSubs(found)
			return found
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := sub + "." + domain
			ips, err := res.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}
			mu.Lock()
			found = append(found, SubResult{Subdomain: fqdn, IPs: ips})
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	sortSubs(found)
	return found
}

func sortSubs(s []SubResult) {
	sort.Slice(s, func(i, j int) bool { return s[i].Subdomain < s[j].Subdomain })
}

// WhoisResult is a trimmed, structured view of a WHOIS record.
type WhoisResult struct {
	Domain         string   `json:"domain"`
	Registrar      string   `json:"registrar,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
	Status         []string `json:"status,omitempty"`
	Raw            string   `json:"raw,omitempty"`
}

// LookupWhois queries WHOIS for a domain and returns a structured summary
// alongside the raw record. includeRaw controls whether the raw text is kept.
func LookupWhois(ctx context.Context, domain string, includeRaw bool) (*WhoisResult, error) {
	ckey := "whois:" + domain
	if includeRaw {
		ckey += ":raw"
	}
	if v, ok := cacheGet[*WhoisResult](ckey); ok {
		return v, nil
	}
	done := make(chan struct{})
	var raw string
	var qErr error
	go func() {
		defer close(done)
		raw, qErr = whois.Whois(domain)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}
	if qErr != nil {
		return nil, qErr
	}

	out := &WhoisResult{Domain: domain}
	if includeRaw {
		out.Raw = raw
	}
	parsed, perr := whoisparser.Parse(raw)
	if perr != nil {
		// Parsing can fail on unusual TLDs; still return the raw record.
		out.Raw = raw
		cacheSet(ckey, out, ttlWhois)
		return out, nil
	}
	if parsed.Registrar != nil {
		out.Registrar = parsed.Registrar.Name
	}
	if parsed.Domain != nil {
		out.CreatedDate = parsed.Domain.CreatedDate
		out.UpdatedDate = parsed.Domain.UpdatedDate
		out.ExpirationDate = parsed.Domain.ExpirationDate
		out.NameServers = parsed.Domain.NameServers
		out.Status = parsed.Domain.Status
	}
	cacheSet(ckey, out, ttlWhois)
	return out, nil
}
