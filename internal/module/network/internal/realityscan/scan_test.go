package realityscan

import (
	"context"
	"net"
	"testing"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
	"github.com/perfect-panel/server/internal/module/network/entity/node"
)

func TestNeighborsStayInsideTheRadiusAndSkipPrivateSpace(t *testing.T) {
	public := neighborTargets(net.ParseIP("203.0.113.10"), 2, 443)
	if len(public) != 4 {
		t.Fatalf("public neighbors = %d, want 4", len(public))
	}
	if got := neighborTargets(net.ParseIP("192.168.1.10"), 4, 443); len(got) != 0 {
		t.Fatalf("private neighbors = %d, want none", len(got))
	}
	if got := neighborTargets(net.ParseIP("2001:db8::1"), 4, 443); len(got) != 0 {
		t.Fatalf("ipv6 neighbors = %d, want none", len(got))
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
		Feasible: true, Score: 12000, Source: "candidate", DialHost: "www.microsoft.com",
		IP: "1.1.1.1", Port: 443, CertDomain: "www.microsoft.com",
	}
	current := dto.RealityScanResult{Feasible: false, DialHost: "old.example", Origin: "old.example", Port: 443}
	switches := svc.apply(context.Background(), []*node.Server{server}, DefaultConfig(), []dto.RealityScanResult{current, best}, best, true)
	if len(switches) != 1 || switches[0].Reason != "current_down" || switches[0].ToSNI != "www.microsoft.com" {
		t.Fatalf("switches = %#v", switches)
	}
	updated, err := server.UnmarshalProtocols()
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].SNI != "www.microsoft.com" || updated[0].RealityServerAddr != "www.microsoft.com" || updated[0].RealityPrivateKey != "priv" {
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
