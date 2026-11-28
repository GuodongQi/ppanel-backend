package realityscan

import (
	"context"
	"strings"
)

// eduDomains are homepages the scanner may try when a VLESS server's /24 has
// no usable neighbor. Each one is resolved and kept only when its address is
// in that server's country and state, or a nearby city.
var eduDomains = []string{
	"ua.edu", "alaska.edu", "arizona.edu", "uark.edu", "berkeley.edu", "ucla.edu", "stanford.edu",
	"colorado.edu", "yale.edu", "udel.edu", "ufl.edu", "gatech.edu", "hawaii.edu", "uidaho.edu",
	"illinois.edu", "uchicago.edu", "purdue.edu", "uiowa.edu", "ku.edu", "uky.edu", "lsu.edu",
	"umaine.edu", "umd.edu", "mit.edu", "harvard.edu", "umich.edu", "umn.edu", "olemiss.edu",
	"missouri.edu", "montana.edu", "unl.edu", "unr.edu", "unh.edu", "rutgers.edu", "princeton.edu",
	"unm.edu", "nyu.edu", "cornell.edu", "unc.edu", "duke.edu", "und.edu", "osu.edu", "ou.edu",
	"uoregon.edu", "upenn.edu", "psu.edu", "brown.edu", "sc.edu", "usd.edu", "utk.edu", "utexas.edu",
	"utah.edu", "uvm.edu", "virginia.edu", "washington.edu", "wvu.edu", "wisc.edu", "uwyo.edu",
	"tsinghua.edu.cn", "pku.edu.cn", "cuhk.edu.hk", "nus.edu.sg", "unimelb.edu.au", "sydney.edu.au",
}

const maxEduProbes = 8

func eduTargets(ctx context.Context, server Place, resolve resolver, locate Locator) []target {
	if server.Country == "" || resolve == nil || locate == nil {
		return nil
	}
	out := make([]target, 0, maxEduProbes)
	for _, domain := range eduDomains {
		if !eduName(domain) || excludedDomain(domain) {
			continue
		}
		ips, err := resolve(ctx, domain)
		if err != nil {
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
			break
		}
		if len(out) >= maxEduProbes {
			break
		}
	}
	return out
}

func eduName(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.HasSuffix(domain, ".edu") || strings.Contains(domain, ".edu.")
}
