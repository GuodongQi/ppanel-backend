package realityscan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
	"github.com/perfect-panel/server/internal/module/network/entity/node"
)

func TestSlash24StaysInsideThePrefixAndSkipsPrivateSpace(t *testing.T) {
	public := slash24Targets(net.ParseIP("203.0.113.10"), 443)
	if len(public) != 253 {
		t.Fatalf("public /24 = %d, want 253", len(public))
	}
	for _, item := range public {
		if item.dialHost == "203.0.113.10" || item.port != 443 || !same24(net.ParseIP(item.dialHost), netip.MustParseAddr("203.0.113.10")) {
			t.Fatalf("target %s is outside 203.0.113.10/24", item.dialHost)
		}
	}
	if got := slash24Targets(net.ParseIP("192.168.1.10"), 443); len(got) != 0 {
		t.Fatalf("private /24 = %d, want none", len(got))
	}
	if got := slash24Targets(net.ParseIP("2001:db8::1"), 443); len(got) != 0 {
		t.Fatalf("ipv6 /24 = %d, want none", len(got))
	}
}

func TestNormalizeRejectsAnOpenRadius(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Radius = 1000
	if _, err := Normalize(cfg); err == nil {
		t.Fatal("radius 1000 was accepted")
	}
	cfg.Radius = 8
	cfg.Candidates = []string{" www.Example.com ", "www.example.com"}
	got, err := Normalize(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != 1 || got.Candidates[0] != "www.Example.com" {
		t.Fatalf("candidates = %#v", got.Candidates)
	}
}

func TestDecideKeepsAHealthyTargetInsideTheMargin(t *testing.T) {
	current := dto.RealityScanResult{Feasible: true, Score: 9000, DialHost: "a.example", Port: 443, CertDomain: "a.example"}
	best := dto.RealityScanResult{Feasible: true, Score: 9200, DialHost: "b.example", Port: 443, CertDomain: "b.example", IP: "203.0.113.8"}
	replace, reason := decide(current, true, best, 400, true)
	if replace || reason != "margin" {
		t.Fatalf("replace=%v reason=%s, want margin", replace, reason)
	}
	replace, reason = decide(current, true, best, 100, true)
	if !replace || reason != "higher_score" {
		t.Fatalf("replace=%v reason=%s, want higher_score", replace, reason)
	}
	replace, reason = decide(current, true, best, 100, false)
	if replace || reason != "cooldown" {
		t.Fatalf("replace=%v reason=%s, want cooldown", replace, reason)
	}
}

func TestDecideReplacesADeadTargetImmediately(t *testing.T) {
	current := dto.RealityScanResult{Feasible: false, DialHost: "a.example", Port: 443}
	best := dto.RealityScanResult{Feasible: true, Score: 1000, DialHost: "b.example", Port: 443, CertDomain: "b.example"}
	replace, reason := decide(current, true, best, 400, false)
	if !replace || reason != "current_down" {
		t.Fatalf("replace=%v reason=%s, want current_down", replace, reason)
	}
}

func TestDailyRunIsDueOnceAfterTheConfiguredTime(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DailyTime = "04:00"
	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 28, 3, 59, 0, 0, loc)
	if due(cfg, dto.RealityScanReport{}, now) {
		t.Fatal("scan was due before 04:00")
	}
	now = now.Add(time.Minute)
	if !due(cfg, dto.RealityScanReport{}, now) {
		t.Fatal("scan was not due at 04:00")
	}
	if due(cfg, dto.RealityScanReport{LastCompleted: "2026-11-28"}, now) {
		t.Fatal("scan was due again after it completed")
	}
}

func TestApplySwitchesTheCamouflageAndKeepsTheKey(t *testing.T) {
	server := &node.Server{Id: 7, Name: "edge"}
	if err := server.MarshalProtocols([]node.Protocol{{
		Type: "vless", Enable: true, Security: "reality", Port: 443,
		SNI: "old.example", RealityServerAddr: "old.example", RealityServerPort: 443,
		RealityPrivateKey: "priv", RealityPublicKey: "pub", RealityShortId: "abcd",
	}}); err != nil {
		t.Fatal(err)
	}
	nodes := &memNodes{servers: []*node.Server{server}, stored: map[int64]string{server.Id: server.Protocols}}
	svc := New(Deps{Nodes: nodes, Now: func() time.Time { return time.Date(2026, 11, 28, 4, 0, 0, 0, time.UTC) }})
	best := dto.RealityScanResult{
		Feasible: true, Score: 12000, Source: "candidate", DialHost: "mit.edu",
		IP: "1.1.1.1", Port: 443, CertDomain: "mit.edu",
	}
	current := dto.RealityScanResult{Feasible: false, DialHost: "old.example", Origin: "old.example", Port: 443}
	site := serverSite{server: server}
	switches := svc.apply(context.Background(), []serverSite{site}, DefaultConfig(), []dto.RealityScanResult{current, best}, map[int64]dto.RealityScanResult{server.Id: best}, true)
	if len(switches) != 1 || switches[0].Reason != "current_down" || switches[0].ToSNI != "mit.edu" {
		t.Fatalf("switches = %#v", switches)
	}
	updated, err := server.UnmarshalProtocols()
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].SNI != "mit.edu" || updated[0].RealityServerAddr != "mit.edu" || updated[0].RealityPrivateKey != "priv" {
		t.Fatalf("protocol = %#v", updated[0])
	}
	if !nodes.cleared {
		t.Fatal("server cache was not cleared")
	}
}

type memNodes struct {
	servers []*node.Server
	stored  map[int64]string
	cleared bool
}

func (m *memNodes) FilterServerList(context.Context, *node.FilterParams) (int64, []*node.Server, error) {
	return int64(len(m.servers)), m.servers, nil
}

func (m *memNodes) UpdateServerProtocolsIfCurrent(_ context.Context, id int64, current, updated string) (bool, error) {
	if m.stored[id] != current {
		return false, nil
	}
	m.stored[id] = updated
	for _, server := range m.servers {
		if server.Id == id {
			server.Protocols = updated
		}
	}
	return true, nil
}

func (m *memNodes) ClearServerCache(context.Context, int64) error {
	m.cleared = true
	return nil
}

func TestPopularDomainsAndCDNOrganizationsAreExcluded(t *testing.T) {
	for _, domain := range []string{"www.cloudflare.com", "www.apple.com", "login.microsoftonline.com", "www.google.com", "s3.amazonaws.com", "a.akamai.net", "example.fastly.net"} {
		if !excludedDomain(domain) {
			t.Fatalf("%s should be excluded", domain)
		}
	}
	if excludedDomain("mit.edu") || excludedDomain("cs.stanford.edu") {
		t.Fatal("education domains should remain available")
	}
	if !excludedOrg("Cloudflare, Inc.") || !excludedOrg("Akamai Technologies") {
		t.Fatal("CDN organizations should be excluded")
	}
}

func TestPlaceFollowsTheVLESSServerNotAnotherNetwork(t *testing.T) {
	server := Place{ASN: 16509, ASOrg: "Amazon.com, Inc.", Country: "US", Region: "California", City: "San Jose", Latitude: 37.3, Longitude: -121.9}
	panel := Place{ASN: 13335, ASOrg: "Cloudflare, Inc.", Country: "US", Region: "California", City: "San Francisco"}
	neighbor := Place{ASN: 16509, ASOrg: "Amazon.com, Inc.", Country: "US", Region: "California", City: "San Jose"}
	if !alignsWithServer(neighbor, server) {
		t.Fatal("same ASN and area as the VLESS server should pass")
	}
	if alignsWithServer(panel, server) {
		t.Fatal("a different ASN with a CDN organization should fail")
	}
	if blockedNetwork(neighbor, server) {
		t.Fatal("the VLESS server's own Amazon ASN is not a CDN edge")
	}
}

func TestEducationFallbackMatchesTheServerArea(t *testing.T) {
	server := Place{ASN: 16509, Country: "US", Region: "Massachusetts", City: "Cambridge", Latitude: 42.37, Longitude: -71.1}
	locate := func(ip string) (Place, bool) {
		if ip == "18.9.22.169" {
			return Place{ASN: 3, ASOrg: "Massachusetts Institute of Technology", Country: "US", Region: "Massachusetts", City: "Cambridge", Latitude: 42.36, Longitude: -71.09}, true
		}
		return Place{ASN: 13335, ASOrg: "Cloudflare", Country: "US", Region: "California"}, true
	}
	resolve := func(_ context.Context, domain string) ([]net.IP, error) {
		if domain == "mit.edu" {
			return []net.IP{net.ParseIP("18.9.22.169")}, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	got := eduTargets(context.Background(), server, resolve, locate)
	if len(got) != 1 || got[0].origin != "mit.edu" || got[0].dialHost != "18.9.22.169" {
		t.Fatalf("edu targets = %#v", got)
	}
}

func TestThreadsCannotExceedTwenty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Threads = 21
	if _, err := Normalize(cfg); err == nil {
		t.Fatal("threads above 20 should fail")
	}
	cfg.Threads = 20
	if _, err := Normalize(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateDomainStaysTheDestination(t *testing.T) {
	got := destinationAddress(dto.RealityScanResult{Source: "candidate", DialHost: "www.microsoft.com", IP: "1.2.3.4"})
	if got != "www.microsoft.com" {
		t.Fatalf("destination = %s", got)
	}
	got = destinationAddress(dto.RealityScanResult{Source: "neighbor", DialHost: "203.0.113.9", IP: "203.0.113.9", CertDomain: "cdn.example"})
	if got != "203.0.113.9" {
		t.Fatalf("neighbor destination = %s", got)
	}
}
