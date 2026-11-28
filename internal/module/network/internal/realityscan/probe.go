package realityscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
)

func probeAll(ctx context.Context, items []target, threads, timeoutSeconds, maxCertBytes int) []dto.RealityScanResult {
	if len(items) == 0 {
		return nil
	}
	if threads < 1 {
		threads = 1
	}
	jobs := make(chan target)
	results := make(chan dto.RealityScanResult)
	var workers sync.WaitGroup
	for i := 0; i < threads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				results <- probeOne(ctx, item, time.Duration(timeoutSeconds)*time.Second, maxCertBytes)
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

func probeOne(ctx context.Context, item target, timeout time.Duration, maxCertBytes int) dto.RealityScanResult {
	result := dto.RealityScanResult{
		Origin:   item.origin,
		DialHost: item.dialHost,
		Source:   item.source,
		Port:     item.port,
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
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
		MinVersion:         tls.VersionTLS12,
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
	for _, cert := range state.PeerCertificates {
		result.CertBytes += len(cert.Raw)
		if certName(cert) != "" {
			leaf = cert
		}
	}
	result.CertDomain = certName(leaf)
	result.CertIssuer = strings.Join(leaf.Issuer.Organization, " | ")
	score(&result, maxCertBytes)
	return result
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
		if concreteName(name) {
			return name
		}
	}
	if concreteName(cert.Subject.CommonName) {
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
	if result.Curve != tls.X25519.String() && result.Curve != tls.X25519MLKEM768.String() {
		return
	}
	if result.CertDomain == "" || result.CertIssuer == "" || result.CertBytes <= 0 || result.CertBytes > maxCertBytes {
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
	case "server", "seed":
		value += 200
	}
	if result.Curve == tls.X25519.String() {
		value += 150
	}
	result.Feasible = true
	result.Score = value
}
