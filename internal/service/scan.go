package service

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortStatus describes the result of probing a single TCP port.
type PortStatus struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// ScanResult aggregates a host's port scan.
type ScanResult struct {
	Host      string       `json:"host"`
	Scanned   int          `json:"scanned"`
	OpenCount int          `json:"open_count"`
	Ports     []PortStatus `json:"ports"`
	Elapsed   string       `json:"elapsed"`
}

// commonServices maps well-known ports to service names for quick labeling.
var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
	5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
	27017: "mongodb",
}

// ScanPorts probes the given TCP ports on a host with bounded concurrency.
// It returns only ports it managed to test before the context expired.
func ScanPorts(ctx context.Context, host string, ports []int, timeout time.Duration, concurrency int, grabBanner bool) *ScanResult {
	start := time.Now()
	if concurrency <= 0 {
		concurrency = 100
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]PortStatus, 0, len(ports))

	for _, p := range ports {
		select {
		case <-ctx.Done():
			wg.Wait()
			return finalize(host, results, start)
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			st := probePort(ctx, host, port, timeout, grabBanner)
			mu.Lock()
			results = append(results, st)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return finalize(host, results, start)
}

func finalize(host string, results []PortStatus, start time.Time) *ScanResult {
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	open := 0
	for _, r := range results {
		if r.Open {
			open++
		}
	}
	return &ScanResult{
		Host:      host,
		Scanned:   len(results),
		OpenCount: open,
		Ports:     results,
		Elapsed:   time.Since(start).Round(time.Millisecond).String(),
	}
}

func probePort(ctx context.Context, host string, port int, timeout time.Duration, grabBanner bool) PortStatus {
	st := PortStatus{Port: port, Service: commonServices[port]}
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return st
	}
	defer conn.Close()
	st.Open = true
	if grabBanner {
		st.Banner = grab(conn, port, timeout)
	}
	return st
}

// grab attempts a best-effort service banner read. For silent protocols like
// HTTP it nudges the server with a minimal request first.
func grab(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if port == 80 || port == 8080 || port == 8000 {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}
	reader := bufio.NewReader(conn)
	buf := make([]byte, 512)
	n, _ := reader.Read(buf)
	if n == 0 {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	// Collapse to the first line for HTTP-style multi-line banners.
	if i := strings.IndexAny(banner, "\r\n"); i > 0 {
		banner = banner[:i]
	}
	return sanitize(banner)
}

// sanitize strips non-printable bytes so banners are safe to return as JSON.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// ParsePortSpec expands a spec like "22,80,443,8000-8100" into a sorted,
// de-duplicated slice, capped at maxPorts for safety.
func ParsePortSpec(spec string, maxPorts int) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("no ports specified")
	}
	set := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range: %q", part)
			}
			for p := lo; p <= hi; p++ {
				set[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %q", part)
			}
			set[p] = struct{}{}
		}
		if len(set) > maxPorts {
			return nil, fmt.Errorf("too many ports requested (max %d)", maxPorts)
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// TopPorts returns a curated list of the most common ports to scan by default.
func TopPorts() []int {
	ports := make([]int, 0, len(commonServices))
	for p := range commonServices {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
