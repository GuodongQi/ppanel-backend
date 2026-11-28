package realityscan

import "strings"

// excludedSuffixes are the large CDNs and popular sites a Reality camouflage
// destination must not use. Matching is on the registrable suffix.
var excludedSuffixes = []string{
	"cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
	"apple.com", "icloud.com", "cdn-apple.com", "apple-dns.net",
	"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
	"windows.net", "windows.com", "live.com", "outlook.com", "msn.com",
	"azure.com", "azureedge.net", "azurefd.net", "trafficmanager.net", "bing.com",
	"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
	"youtube.com", "gmail.com", "ggpht.com", "gvt1.com", "gvt2.com",
	"amazon.com", "amazonaws.com", "cloudfront.net", "amazontrust.com",
	"akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "akamai.com",
	"fastly.net", "fastlylb.net", "fastly.com",
	"facebook.com", "fbcdn.net", "instagram.com", "meta.com", "cdninstagram.com",
	"netflix.com", "nflxvideo.net", "nflximg.net",
	"incapsula.com", "imperva.com",
	"stackpathdns.com", "stackpathcdn.com",
	"edgecastcdn.net",
	"cdn77.org", "cdn77.com",
	"b-cdn.net", "bunnycdn.com",
	"alicdn.com", "aliyuncs.com", "alibaba.com",
	"qcloud.com", "myqcloud.com", "tencent.com",
}

var excludedIssuers = []string{
	"cloudflare", "akamai", "fastly", "cloudfront", "amazon", "google",
	"microsoft", "apple", "incapsula", "imperva", "stackpath", "edgecast",
	"cdn77", "bunny", "alibaba", "tencent", "meta", "facebook", "netflix",
}

// excludedDomain reports whether name belongs to a large CDN or a popular site.
func excludedDomain(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	for _, suffix := range excludedSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// excludedIssuer reports whether a certificate issuer is a CDN edge.
func excludedIssuer(issuer string) bool {
	issuer = strings.ToLower(issuer)
	if issuer == "" {
		return false
	}
	for _, needle := range excludedIssuers {
		if strings.Contains(issuer, needle) {
			return true
		}
	}
	return false
}

// excludedOrg reports whether an ASN organization is a CDN or a popular network.
func excludedOrg(org string) bool {
	return excludedIssuer(org)
}
