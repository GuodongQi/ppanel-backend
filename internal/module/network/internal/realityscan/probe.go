package realityscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
)

const (
	scanPort       = 443
	maxLatencyMS   = 800
	probePace      = 100 * time.Millisecond
	resolveTimeout = 3 * time.Second
)

type resolver func(ctx context.Context, host string) ([]net.IP, error)

type statusFunc func(ctx context.Context, ip, name string, timeout time.Duration) (int, error)

func probeAll(ctx context.Context, items []target, threads, timeoutSeconds, maxCertBytes int, resolve resolver, status statusFunc) []dto.RealityScanResult {
	if len(items) == 0 {
		return nil
	}
	if threads < 1 {
		threads = 1
	}
	if threads > maxThreads {
		threads = maxThreads
	}
	if resolve == nil {
		resolve = defaultResolve
	}
	if status == nil {
		status = defaultStatus
	}
	jobs := make(chan target)
	results := make(chan dto.RealityScanResult)
	pace := &paceGate{gap: probePace}
	var workers sync.WaitGroup
	for i := 0; i < threads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				if err := pace.wait(ctx); err != nil {
					return
				}
				results <- probeOne(ctx, item, time.Duration(timeoutSeconds)*time.Second, maxCertBytes, resolve, status)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range items {
			select {
			case <-ctx.Done():
				return
			case jobs <- item:
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	out := make([]dto.RealityScanResult, 0, len(items))
	for item := range results {
		out = append(out, item)
	}
	return out
}

type paceGate struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

func (g *paceGate) wait(ctx context.Context) error {
	g.mu.Lock()
	slot := g.next
	if slot.Before(time.Now()) {
		slot = time.Now()
	}
	g.next = slot.Add(g.gap)
	g.mu.Unlock()
	timer := time.NewTimer(time.Until(slot))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func probeOne(ctx context.Context, item target, timeout time.Duration, maxCertBytes int, resolve resolver, status statusFunc) dto.RealityScanResult {
	result := dto.RealityScanResult{
		Origin:   item.origin,
		DialHost: item.dialHost,
		Source:   item.source,
		Port:     item.port,
	}
	if ctx.Err() != nil {
		result.Error = "cancelled"
		return result
	}
	started := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", net.JoinHostPort(item.dialHost, strconv.Itoa(item.port)))
	if err != nil {
		result.Error = "dial failed"
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         item.serverName,
		MinVersion:         tls.VersionTLS13,
	})
	if err = tlsConn.HandshakeContext(dialCtx); err != nil {
		result.Error = "handshake failed"
		return result
	}
	state := tlsConn.ConnectionState()
	result.LatencyMS = int(time.Since(started) / time.Millisecond)
	if result.LatencyMS < 1 {
		result.LatencyMS = 1
	}
	result.IP = remoteIP(conn)
	result.TLS = tls.VersionName(state.Version)
	result.ALPN = state.NegotiatedProtocol
	result.Curve = state.CurveID.String()
	if len(state.PeerCertificates) == 0 {
		result.Error = "no certificate"
		return result
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	for _, cert := range state.PeerCertificates {
		result.CertBytes += len(cert.Raw)
		if certName(cert) != "" {
			leaf = cert
		}
	}
	if leaf.IsCA || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		result.Error = "certificate is not valid"
		return result
	}
	result.CertDomain = certName(leaf)
	result.CertIssuer = strings.Join(leaf.Issuer.Organization, " | ")
	if result.CertIssuer == "" {
		result.CertIssuer = leaf.Issuer.CommonName
	}
	score(&result, maxCertBytes)
	if !result.Feasible {
		return result
	}
	if !resolvesTo(ctx, resolve, result.CertDomain, result.IP) {
		result.Feasible = false
		result.Score = 0
		result.Error = "certificate domain does not resolve to this address"
		return result
	}
	code, err := status(ctx, result.IP, result.CertDomain, timeout)
	if err != nil || !acceptableStatus(code) {
		result.Feasible = false
		result.Score = 0
		result.Error = "direct request was not 200, 301, or 302"
	}
	return result
}

func resolvesTo(ctx context.Context, resolve resolver, name, ip string) bool {
	if resolve == nil || name == "" || ip == "" {
		return false
	}
	ips, err := resolve(ctx, name)
	if err != nil {
		return false
	}
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	for _, item := range ips {
		if item.Equal(want) {
			return true
		}
	}
	return false
}

func acceptableStatus(code int) bool {
	return code == http.StatusOK || code == http.StatusMovedPermanently || code == http.StatusFound
}

func defaultResolve(ctx context.Context, host string) ([]net.IP, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			out = append(out, addr.IP)
		}
	}
	return out, nil
}

func defaultStatus(ctx context.Context, ip, name string, timeout time.Duration) (int, error) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(scanPort)))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         name,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, nil
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func certName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if concreteName(name) && !excludedDomain(name) {
			return name
		}
	}
	if concreteName(cert.Subject.CommonName) && !excludedDomain(cert.Subject.CommonName) {
		return cert.Subject.CommonName
	}
	return ""
}

func concreteName(name string) bool {
	name = strings.TrimSpace(name)
	return name != "" && !strings.HasPrefix(name, "*.")
}

func score(result *dto.RealityScanResult, maxCertBytes int) {
	result.Feasible = false
	result.Score = 0
	if result.TLS != tls.VersionName(tls.VersionTLS13) || result.ALPN != "h2" {
		return
	}
	if result.LatencyMS <= 0 || result.LatencyMS > maxLatencyMS {
		return
	}
	if result.CertDomain == "" || excludedDomain(result.CertDomain) || excludedIssuer(result.CertIssuer) {
		result.Error = "cdn or popular site"
		return
	}
	if result.CertBytes <= 0 || result.CertBytes > maxCertBytes {
		return
	}
	value := 10000 - result.LatencyMS - result.CertBytes/64
	if value < 0 {
		value = 0
	}
	switch result.Source {
	case "candidate":
		value += 2500
	case "current":
		value += 800
	case "edu":
		value += 400
	case "server", "seed":
		value += 200
	}
	result.Feasible = true
	result.Score = value
}
