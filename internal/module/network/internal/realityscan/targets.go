package realityscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
)

type target struct {
	dialHost   string
	serverName string
	origin     string
	source     string
	port       int
}

func (t target) key() string {
	return strings.ToLower(t.dialHost) + "|" + strconv.Itoa(t.port) + "|" + strings.ToLower(t.serverName)
}

// buildTargets collects candidate domains, the current Reality destinations
// and a bounded public-IPv4 neighborhood around each seed. The neighborhood
// stops at maxTargets; candidates and current destinations are kept first.
func buildTargets(ctx context.Context, cfg dto.RealityScanConfig, currents []target, seeds []string) ([]target, bool) {
	seen := map[string]struct{}{}
	out := make([]target, 0, 64)
	add := func(item target) bool {
		if item.dialHost == "" || item.port == 0 {
			return true
		}
		if _, ok := seen[item.key()]; ok {
			return true
		}
		if len(out) >= maxTargets {
			return false
		}
		seen[item.key()] = struct{}{}
		out = append(out, item)
		return true
	}

	for _, domain := range cfg.Candidates {
		if !add(target{dialHost: domain, serverName: domain, origin: domain, source: "candidate", port: cfg.Port}) {
			return out, true
		}
	}
	for _, item := range currents {
		if item.port == 0 {
			item.port = cfg.Port
		}
		if !add(item) {
			return out, true
		}
	}

	truncated := false
	for _, seed := range seeds {
		for _, item := range expandSeed(ctx, seed, cfg.Radius, cfg.Port) {
			if !add(item) {
				truncated = true
				return out, truncated
			}
		}
	}
	return out, truncated
}

func expandSeed(ctx context.Context, seed string, radius, port int) []target {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return nil
	}
	var out []target
	if ip := net.ParseIP(seed); ip != nil {
		out = append(out, target{dialHost: ip.String(), origin: ip.String(), source: "seed", port: port})
		out = append(out, neighborTargets(ip, radius, port)...)
		return out
	}
	out = append(out, target{dialHost: seed, serverName: seed, origin: seed, source: "seed", port: port})
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, seed)
	if err != nil {
		return out
	}
	for _, ip := range ips {
		out = append(out, neighborTargets(ip.IP, radius, port)...)
	}
	return out
}

func neighborTargets(ip net.IP, radius, port int) []target {
	addr, ok := publicIPv4(ip)
	if !ok {
		return nil
	}
	out := make([]target, 0, radius*2)
	for delta := -radius; delta <= radius; delta++ {
		if delta == 0 {
			continue
		}
		next, ok := shiftIPv4(addr, delta)
		if !ok || !isPublicIPv4(next) {
			continue
		}
		host := next.String()
		out = append(out, target{dialHost: host, origin: host, source: "neighbor", port: port})
	}
	return out
}

func publicIPv4(ip net.IP) (netip.Addr, bool) {
	parsed := net.ParseIP(ip.String())
	if parsed == nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(parsed.String())
	if err != nil || !isPublicIPv4(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

func isPublicIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate()
}

func shiftIPv4(addr netip.Addr, delta int) (netip.Addr, bool) {
	parts := addr.As4()
	value := int(parts[0])<<24 | int(parts[1])<<16 | int(parts[2])<<8 | int(parts[3])
	value += delta
	if value < 0 || value > 0xffffffff {
		return netip.Addr{}, false
	}
	var next [4]byte
	next[0] = byte(value >> 24)
	next[1] = byte(value >> 16)
	next[2] = byte(value >> 8)
	next[3] = byte(value)
	return netip.AddrFrom4(next), true
}
