package realityscan

import (
	"context"
	"strings"
)

const maxEduProbes = 8

type eduFinder func(ctx context.Context, place Place) ([]string, error)

func eduTargets(ctx context.Context, server Place, resolve resolver, locate Locator, find eduFinder) ([]target, []string, error) {
	if server.Country == "" || resolve == nil || locate == nil {
		return nil, nil, nil
	}
	if find == nil {
		find = defaultEduDomains
	}
	domains, err := find(ctx, server)
	if err != nil {
		return nil, nil, err
	}
	out := make([]target, 0, maxEduProbes)
	kept := make([]string, 0, maxEduProbes)
	seen := map[string]struct{}{}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if !eduName(domain) || excludedDomain(domain) {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		ips, lookupErr := resolve(ctx, domain)
		if lookupErr != nil {
			continue
		}
		for _, ip := range ips {
			addr, ok := publicIPv4(ip)
			if !ok {
				continue
			}
			place, found := locate(addr.String())
			if !found || blockedNetwork(place, server) || !sameArea(place, server) {
				continue
			}
			out = append(out, target{
				dialHost: addr.String(), serverName: domain, origin: domain, source: "edu", port: 443,
			})
			kept = append(kept, domain)
			break
		}
		if len(out) >= maxEduProbes {
			break
		}
	}
	return out, kept, nil
}

func eduName(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(strings.Trim(domain, ".")))
	return strings.HasSuffix(domain, ".edu") || strings.Contains(domain, ".edu.")
}
