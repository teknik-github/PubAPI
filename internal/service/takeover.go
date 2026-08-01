package service

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// takeoverSignatures maps takeover-prone services to the CNAME targets that
// point at them and the response-body fingerprint of an unclaimed resource.
var takeoverSignatures = []struct {
	Service     string
	Patterns    []string
	Fingerprint string
}{
	{"GitHub Pages", []string{"github.io"}, "There isn't a GitHub Pages site here"},
	{"Heroku", []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, "No such app"},
	{"AWS S3", []string{"s3.amazonaws.com", "s3-website", "amazonaws.com"}, "NoSuchBucket"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable"},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain"},
	{"Surge.sh", []string{"surge.sh"}, "project not found"},
	{"Bitbucket", []string{"bitbucket.io"}, "Repository not found"},
	{"Ghost", []string{"ghost.io"}, "The thing you were looking for is no longer here"},
	{"Pantheon", []string{"pantheonsite.io"}, "The gods are wise"},
	{"Tumblr", []string{"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist"},
	{"WordPress", []string{"wordpress.com"}, "Do you want to register"},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed"},
	{"Read the Docs", []string{"readthedocs.io"}, "unknown to Read the Docs"},
	{"Unbounce", []string{"unbouncepages.com"}, "The requested URL was not found on this server"},
	{"Cargo", []string{"cargocollective.com"}, "404 Not Found"},
	{"Azure", []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net", "azure-api.net"}, "404 Web Site not found"},
}

// TakeoverEntry is a single subdomain evaluated for takeover.
type TakeoverEntry struct {
	Subdomain string `json:"subdomain"`
	CNAME     string `json:"cname"`
	Service   string `json:"service"`
	Status    string `json:"status"` // vulnerable | potential | points_to_service
	Evidence  string `json:"evidence,omitempty"`
}

// TakeoverResult aggregates a takeover sweep.
type TakeoverResult struct {
	Domain     string          `json:"domain"`
	Checked    int             `json:"checked"`
	Vulnerable []TakeoverEntry `json:"vulnerable"`
	Potential  []TakeoverEntry `json:"potential"`
	Findings   []Finding       `json:"findings"`
}

const maxTakeoverCandidates = 400

// DetectTakeovers checks each candidate subdomain's CNAME against known
// takeover-prone services and probes the response for an unclaimed fingerprint.
func DetectTakeovers(ctx context.Context, domain string, candidates []string, concurrency int, timeout time.Duration) TakeoverResult {
	out := TakeoverResult{Domain: domain, Vulnerable: []TakeoverEntry{}, Potential: []TakeoverEntry{}, Findings: []Finding{}}
	if concurrency <= 0 {
		concurrency = 50
	}

	// Deduplicate and cap the candidate set.
	seen := make(map[string]struct{})
	uniq := make([]string, 0, len(candidates))
	for _, c := range candidates {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		uniq = append(uniq, c)
		if len(uniq) >= maxTakeoverCandidates {
			break
		}
	}

	client := newHTTPClient(timeout)
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, sub := range uniq {
		select {
		case <-ctx.Done():
			wg.Wait()
			finalizeTakeover(&out)
			return out
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(fqdn string) {
			defer wg.Done()
			defer func() { <-sem }()

			cname := queryCNAME(fqdn, timeout)
			if cname == "" || cname == fqdn {
				return
			}
			svc, fp := matchTakeoverService(cname)
			if svc == "" {
				return
			}

			mu.Lock()
			out.Checked++
			mu.Unlock()

			entry := TakeoverEntry{Subdomain: fqdn, CNAME: cname, Service: svc}
			_, body := getText(ctx, client, "http://"+fqdn)
			switch {
			case fp != "" && strings.Contains(body, fp):
				entry.Status = "vulnerable"
				entry.Evidence = "fingerprint matched: " + fp
			case !hostResolves(ctx, fqdn):
				entry.Status = "potential"
				entry.Evidence = "dangling CNAME to " + svc + " (does not resolve)"
			default:
				entry.Status = "points_to_service"
			}

			mu.Lock()
			switch entry.Status {
			case "vulnerable":
				out.Vulnerable = append(out.Vulnerable, entry)
			case "potential":
				out.Potential = append(out.Potential, entry)
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	finalizeTakeover(&out)
	return out
}

func finalizeTakeover(out *TakeoverResult) {
	sort.Slice(out.Vulnerable, func(i, j int) bool { return out.Vulnerable[i].Subdomain < out.Vulnerable[j].Subdomain })
	sort.Slice(out.Potential, func(i, j int) bool { return out.Potential[i].Subdomain < out.Potential[j].Subdomain })
	if len(out.Vulnerable) > 0 {
		out.Findings = append(out.Findings, Finding{"high", "Subdomain takeover terkonfirmasi pada " + strconv.Itoa(len(out.Vulnerable)) + " host."})
	}
	if len(out.Potential) > 0 {
		out.Findings = append(out.Findings, Finding{"medium", "Dangling CNAME berpotensi takeover pada " + strconv.Itoa(len(out.Potential)) + " host — verifikasi manual."})
	}
	if len(out.Findings) == 0 {
		out.Findings = append(out.Findings, Finding{"info", "Tidak ada indikasi takeover terdeteksi."})
	}
}

func matchTakeoverService(cname string) (service, fingerprint string) {
	for _, sig := range takeoverSignatures {
		for _, p := range sig.Patterns {
			if strings.Contains(cname, p) {
				return sig.Service, sig.Fingerprint
			}
		}
	}
	return "", ""
}

// queryCNAME returns the immediate CNAME target for a name, or "" if none.
// It uses a direct DNS query so dangling CNAMEs (target unresolvable) are still
// observed — the key signal for takeover.
func queryCNAME(fqdn string, timeout time.Duration) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	c := &dns.Client{Timeout: timeout}
	for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		r, _, err := c.Exchange(m, server)
		if err != nil || r == nil {
			continue
		}
		for _, ans := range r.Answer {
			if cn, ok := ans.(*dns.CNAME); ok {
				return strings.TrimSuffix(strings.ToLower(cn.Target), ".")
			}
		}
		return ""
	}
	return ""
}

func hostResolves(ctx context.Context, host string) bool {
	var res net.Resolver
	ips, err := res.LookupHost(ctx, host)
	return err == nil && len(ips) > 0
}
