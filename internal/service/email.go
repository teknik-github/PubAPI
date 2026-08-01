package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// EmailSecurity summarizes a domain's email spoofing-protection posture.
type EmailSecurity struct {
	Domain    string     `json:"domain"`
	SPF       SPFInfo    `json:"spf"`
	DMARC     DMARCInfo  `json:"dmarc"`
	DKIM      DKIMInfo   `json:"dkim"`
	DNSSEC    DNSSECInfo `json:"dnssec"`
	Grade     string     `json:"grade"`
	Spoofable bool       `json:"spoofable"`
	Findings  []Finding  `json:"findings"`
}

// Finding is a single graded observation.
type Finding struct {
	Severity string `json:"severity"` // info | low | medium | high
	Message  string `json:"message"`
}

type SPFInfo struct {
	Present   bool   `json:"present"`
	Record    string `json:"record,omitempty"`
	Qualifier string `json:"all_qualifier,omitempty"` // -all, ~all, ?all, +all
	Policy    string `json:"policy,omitempty"`        // hardfail|softfail|neutral|pass-all|none
}

type DMARCInfo struct {
	Present bool   `json:"present"`
	Record  string `json:"record,omitempty"`
	Policy  string `json:"policy,omitempty"` // none|quarantine|reject
	Pct     int    `json:"pct,omitempty"`
	RUA     string `json:"rua,omitempty"`
}

type DKIMInfo struct {
	SelectorsFound []string `json:"selectors_found"`
}

type DNSSECInfo struct {
	Enabled bool `json:"enabled"`
}

// commonDKIMSelectors are probed since selectors are not discoverable from DNS.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2",
	"mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault",
}

// AnalyzeEmailSecurity inspects SPF, DMARC, DKIM, and DNSSEC for a domain.
// extraSelectors are additional DKIM selectors to probe beyond the built-in
// common list (useful for providers that use custom selectors, e.g. "20230601").
func AnalyzeEmailSecurity(ctx context.Context, domain string, extraSelectors []string) (*EmailSecurity, error) {
	es := &EmailSecurity{Domain: domain, Findings: []Finding{}, DKIM: DKIMInfo{SelectorsFound: []string{}}}
	var res net.Resolver
	selectors := mergeSelectors(extraSelectors)
	var wg sync.WaitGroup
	wg.Add(4)

	go func() { defer wg.Done(); es.SPF = analyzeSPF(ctx, &res, domain) }()
	go func() { defer wg.Done(); es.DMARC = analyzeDMARC(ctx, &res, domain) }()
	go func() { defer wg.Done(); es.DKIM = probeDKIM(ctx, &res, domain, selectors) }()
	go func() { defer wg.Done(); es.DNSSEC = checkDNSSEC(domain) }()
	wg.Wait()

	gradeEmail(es)
	return es, nil
}

// mergeSelectors returns the common DKIM selectors plus any deduplicated extras.
func mergeSelectors(extra []string) []string {
	out := make([]string, 0, len(commonDKIMSelectors)+len(extra))
	out = append(out, commonDKIMSelectors...)
	for _, s := range extra {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !containsStr(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func analyzeSPF(ctx context.Context, res *net.Resolver, domain string) SPFInfo {
	info := SPFInfo{}
	txts, err := res.LookupTXT(ctx, domain)
	if err != nil {
		return info
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			info.Present = true
			info.Record = t
			info.Qualifier, info.Policy = spfAllPolicy(t)
			break
		}
	}
	return info
}

func spfAllPolicy(record string) (qualifier, policy string) {
	fields := strings.Fields(record)
	for _, f := range fields {
		switch strings.ToLower(f) {
		case "-all":
			return "-all", "hardfail"
		case "~all":
			return "~all", "softfail"
		case "?all":
			return "?all", "neutral"
		case "+all":
			return "+all", "pass-all"
		}
	}
	return "", "none"
}

func analyzeDMARC(ctx context.Context, res *net.Resolver, domain string) DMARCInfo {
	info := DMARCInfo{}
	txts, err := res.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return info
	}
	for _, t := range txts {
		if !strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			continue
		}
		info.Present = true
		info.Record = t
		for _, part := range strings.Split(t, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			switch key {
			case "p":
				info.Policy = strings.ToLower(val)
			case "pct":
				if n, err := strconv.Atoi(val); err == nil {
					info.Pct = n
				}
			case "rua":
				info.RUA = val
			}
		}
		break
	}
	return info
}

func probeDKIM(ctx context.Context, res *net.Resolver, domain string, selectors []string) DKIMInfo {
	info := DKIMInfo{SelectorsFound: []string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sel := range selectors {
		wg.Add(1)
		go func(selector string) {
			defer wg.Done()
			name := selector + "._domainkey." + domain
			txts, err := res.LookupTXT(ctx, name)
			if err != nil {
				return
			}
			for _, t := range txts {
				low := strings.ToLower(t)
				if strings.Contains(low, "v=dkim1") || strings.Contains(low, "k=rsa") || strings.Contains(low, "p=") {
					mu.Lock()
					info.SelectorsFound = append(info.SelectorsFound, selector)
					mu.Unlock()
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	return info
}

// checkDNSSEC queries for a DNSKEY record via a public resolver; its presence
// indicates the zone is signed.
func checkDNSSEC(domain string) DNSSECInfo {
	info := DNSSECInfo{}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := &dns.Client{Timeout: 4 * time.Second}
	for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		r, _, err := c.Exchange(m, server)
		if err != nil || r == nil {
			continue
		}
		for _, ans := range r.Answer {
			if _, ok := ans.(*dns.DNSKEY); ok {
				info.Enabled = true
				return info
			}
		}
		return info // got an authoritative answer with no DNSKEY
	}
	return info
}

// gradeEmail computes a letter grade, spoofability, and human-readable findings.
func gradeEmail(es *EmailSecurity) {
	score := 0.0

	switch es.SPF.Policy {
	case "hardfail":
		score += 2
		es.Findings = append(es.Findings, Finding{"info", "SPF menerapkan hard fail (-all)."})
	case "softfail":
		score += 1
		es.Findings = append(es.Findings, Finding{"low", "SPF hanya soft fail (~all); pertimbangkan -all."})
	case "neutral", "pass-all", "none":
		if es.SPF.Present {
			es.Findings = append(es.Findings, Finding{"medium", "SPF ada tetapi tidak menolak pengirim tak sah (" + es.SPF.Qualifier + ")."})
		}
	}
	if !es.SPF.Present {
		es.Findings = append(es.Findings, Finding{"high", "Tidak ada record SPF."})
	}

	switch es.DMARC.Policy {
	case "reject":
		score += 3
		es.Findings = append(es.Findings, Finding{"info", "DMARC p=reject (perlindungan terkuat)."})
	case "quarantine":
		score += 2
		es.Findings = append(es.Findings, Finding{"low", "DMARC p=quarantine; p=reject lebih kuat."})
	case "none":
		score += 0.5
		es.Findings = append(es.Findings, Finding{"medium", "DMARC p=none — hanya monitoring, tidak mencegah spoofing."})
	default:
		if !es.DMARC.Present {
			es.Findings = append(es.Findings, Finding{"high", "Tidak ada record DMARC — domain rentan spoofing."})
		}
	}

	if len(es.DKIM.SelectorsFound) > 0 {
		score += 1
		es.Findings = append(es.Findings, Finding{"info", fmt.Sprintf("DKIM ditemukan pada selector: %s.", strings.Join(es.DKIM.SelectorsFound, ", "))})
	} else {
		es.Findings = append(es.Findings, Finding{"low", "Tidak ada DKIM pada selector umum (mungkin memakai selector khusus)."})
	}

	if es.DNSSEC.Enabled {
		score += 1
		es.Findings = append(es.Findings, Finding{"info", "DNSSEC aktif."})
	} else {
		es.Findings = append(es.Findings, Finding{"low", "DNSSEC tidak aktif."})
	}

	// A domain is spoofable when DMARC does not enforce (quarantine/reject).
	es.Spoofable = !(es.DMARC.Policy == "reject" || es.DMARC.Policy == "quarantine")

	switch {
	case score >= 6:
		es.Grade = "A"
	case score >= 4.5:
		es.Grade = "B"
	case score >= 3:
		es.Grade = "C"
	case score >= 1.5:
		es.Grade = "D"
	default:
		es.Grade = "F"
	}
}
