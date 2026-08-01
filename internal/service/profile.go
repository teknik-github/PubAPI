package service

import (
	"context"
	"sync"
	"time"
)

// DomainProfile is a consolidated reconnaissance report for a single domain.
type DomainProfile struct {
	Domain        string         `json:"domain"`
	DNS           *DNSRecords    `json:"dns,omitempty"`
	Whois         *WhoisResult   `json:"whois,omitempty"`
	EmailSecurity *EmailSecurity `json:"email_security,omitempty"`
	TLS           *TLSInfo       `json:"tls,omitempty"`
	Headers       *HeaderAudit   `json:"headers,omitempty"`
	Surface       *SurfaceResult `json:"surface,omitempty"`
	Subdomains    SubSummary     `json:"subdomains"`
	Summary       ProfileSummary `json:"summary"`
}

// SubSummary is a compact view of passive subdomain discovery.
type SubSummary struct {
	Found  int      `json:"found"`
	Sample []string `json:"sample"`
}

// ProfileSummary is the at-a-glance risk rollup across all sections.
type ProfileSummary struct {
	EmailGrade       string         `json:"email_grade,omitempty"`
	HeaderGrade      string         `json:"header_grade,omitempty"`
	Spoofable        bool           `json:"spoofable"`
	SubdomainsFound  int            `json:"subdomains_found"`
	TLSDaysLeft      int            `json:"tls_days_until_expiry,omitempty"`
	TLSExpired       bool           `json:"tls_expired"`
	IssuesBySeverity map[string]int `json:"issues_by_severity"`
}

const profileSampleSize = 20

// BuildDomainProfile runs every domain-oriented recon module concurrently and
// consolidates the results. Individual failures degrade gracefully to nil
// sections rather than failing the whole report.
func BuildDomainProfile(ctx context.Context, domain string, timeout time.Duration) *DomainProfile {
	p := &DomainProfile{Domain: domain}
	var wg sync.WaitGroup
	wg.Add(7)

	go func() {
		defer wg.Done()
		if r, err := LookupDNS(ctx, domain); err == nil {
			p.DNS = r
		}
	}()
	go func() {
		defer wg.Done()
		if r, err := LookupWhois(ctx, domain, false); err == nil {
			p.Whois = r
		}
	}()
	go func() {
		defer wg.Done()
		if r, err := AnalyzeEmailSecurity(ctx, domain, nil); err == nil {
			p.EmailSecurity = r
		}
	}()
	go func() {
		defer wg.Done()
		if r, err := InspectTLS(ctx, domain, 443, timeout); err == nil {
			p.TLS = r
		}
	}()
	go func() {
		defer wg.Done()
		if r, err := AuditHeaders(ctx, "https://"+domain, timeout); err == nil {
			p.Headers = r
		}
	}()
	go func() {
		defer wg.Done()
		if r, err := InspectSurface(ctx, "https://"+domain, timeout); err == nil {
			p.Surface = r
		}
	}()
	go func() {
		defer wg.Done()
		// crt.sh can be slow for large domains; give it a generous floor.
		ctTimeout := timeout * 6
		if ctTimeout < 30*time.Second {
			ctTimeout = 30 * time.Second
		}
		names := PassiveSubdomains(ctx, domain, ctTimeout)
		sample := make([]string, 0, profileSampleSize)
		for i, n := range names {
			if i >= profileSampleSize {
				break
			}
			sample = append(sample, n)
		}
		p.Subdomains = SubSummary{Found: len(names), Sample: sample}
	}()
	wg.Wait()

	p.Summary = summarizeProfile(p)
	return p
}

func summarizeProfile(p *DomainProfile) ProfileSummary {
	s := ProfileSummary{
		SubdomainsFound:  p.Subdomains.Found,
		IssuesBySeverity: map[string]int{},
	}
	if p.EmailSecurity != nil {
		s.EmailGrade = p.EmailSecurity.Grade
		s.Spoofable = p.EmailSecurity.Spoofable
		countFindings(s.IssuesBySeverity, p.EmailSecurity.Findings)
	}
	if p.Headers != nil {
		s.HeaderGrade = p.Headers.Grade
	}
	if p.TLS != nil {
		s.TLSDaysLeft = p.TLS.DaysUntilExpiry
		s.TLSExpired = p.TLS.Expired
	}
	if p.Surface != nil {
		countFindings(s.IssuesBySeverity, p.Surface.Findings)
	}
	return s
}

func countFindings(m map[string]int, findings []Finding) {
	for _, f := range findings {
		if f.Severity == "info" {
			continue
		}
		m[f.Severity]++
	}
}
