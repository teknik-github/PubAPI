package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPInfo describes the geolocation and network ownership of an IP address.
type IPInfo struct {
	IP          string   `json:"ip"`
	ASN         string   `json:"asn,omitempty"`
	ASName      string   `json:"as_name,omitempty"`
	ISP         string   `json:"isp,omitempty"`
	Org         string   `json:"org,omitempty"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Region      string   `json:"region,omitempty"`
	City        string   `json:"city,omitempty"`
	Lat         float64  `json:"lat,omitempty"`
	Lon         float64  `json:"lon,omitempty"`
	Reverse     []string `json:"reverse,omitempty"`
}

// LookupIPInfo resolves geolocation and ASN data for an IP via ip-api.com.
// The lookup queries a fixed third-party host, not the target IP itself.
func LookupIPInfo(ctx context.Context, ip string, timeout time.Duration) (*IPInfo, error) {
	if v, ok := cacheGet[*IPInfo]("ip:" + ip); ok {
		return v, nil
	}
	endpoint := "http://ip-api.com/json/" + ip +
		"?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var r struct {
		Status  string  `json:"status"`
		Message string  `json:"message"`
		Country string  `json:"country"`
		CC      string  `json:"countryCode"`
		Region  string  `json:"regionName"`
		City    string  `json:"city"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		ISP     string  `json:"isp"`
		Org     string  `json:"org"`
		As      string  `json:"as"`
		Query   string  `json:"query"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("geoip: unexpected response")
	}
	if r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = "lookup failed"
		}
		return nil, fmt.Errorf("geoip: %s", msg)
	}

	info := &IPInfo{
		IP:          ip,
		ISP:         r.ISP,
		Org:         r.Org,
		Country:     r.Country,
		CountryCode: r.CC,
		Region:      r.Region,
		City:        r.City,
		Lat:         r.Lat,
		Lon:         r.Lon,
	}
	// "as" looks like "AS15169 Google LLC" — split into number and name.
	if fields := strings.Fields(r.As); len(fields) > 0 {
		info.ASN = fields[0]
		if len(fields) > 1 {
			info.ASName = strings.Join(fields[1:], " ")
		}
	}
	// Best-effort reverse DNS.
	var res net.Resolver
	if names, err := res.LookupAddr(ctx, ip); err == nil {
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		info.Reverse = names
	}
	cacheSet("ip:"+ip, info, ttlGeoIP)
	return info, nil
}
