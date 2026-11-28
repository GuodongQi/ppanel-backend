package realityscan

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
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

// slash24Targets lists the other public addresses in ip's /24. The scan is a
// TLS handshake on one port, so the network and broadcast addresses are left
// out along with ip itself.
func slash24Targets(ip net.IP, port int) []target {
	addr, ok := publicIPv4(ip)
	if !ok {
		return nil
	}
	prefix, err := addr.Prefix(24)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	out := make([]target, 0, 253)
	for host := prefix.Addr(); prefix.Contains(host); host = host.Next() {
		if !host.IsValid() || host == addr {
			continue
		}
		octet := host.As4()[3]
		if octet == 0 || octet == 255 || !isPublicIPv4(host) {
			continue
		}
		text := host.String()
		out = append(out, target{dialHost: text, origin: text, source: "neighbor", port: port})
	}
	return out
}

// dedupeTargets keeps the first of each dial target and stops at maxTargets.
func dedupeTargets(items []target) ([]target, bool) {
	seen := map[string]struct{}{}
	out := make([]target, 0, len(items))
	for _, item := range items {
		if item.dialHost == "" || item.port == 0 {
			continue
		}
		if _, ok := seen[item.key()]; ok {
			continue
		}
		if len(out) >= maxTargets {
			return out, true
		}
		seen[item.key()] = struct{}{}
		out = append(out, item)
	}
	return out, false
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

func same24(ip net.IP, site netip.Addr) bool {
	addr, ok := publicIPv4(ip)
	if !ok || !site.IsValid() {
		return false
	}
	left, err := addr.Prefix(24)
	if err != nil {
		return false
	}
	right, err := site.Prefix(24)
	if err != nil {
		return false
	}
	return left.Masked() == right.Masked()
}
