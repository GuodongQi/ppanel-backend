package realityscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxEduSearchDomains = 12

var eduHostPattern = regexp.MustCompile(`(?i)(?:https?://)([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+)`)

func defaultEduDomains(ctx context.Context, place Place) ([]string, error) {
	queries := eduQueries(place)
	if len(queries) == 0 {
		return nil, fmt.Errorf("server location is unknown")
	}
	client := &http.Client{Timeout: 8 * time.Second}
	var found []string
	var lastErr error
	for _, query := range queries {
		for _, endpoint := range []string{
			"https://html.duckduckgo.com/html/?q=",
			"https://www.bing.com/search?q=",
		} {
			body, err := fetchSearch(ctx, client, endpoint+url.QueryEscape(query))
			if err != nil {
				lastErr = err
				continue
			}
			found = append(found, parseEduDomains(body)...)
			found = uniqueEdu(found)
			if len(found) >= maxEduSearchDomains {
				return found[:maxEduSearchDomains], nil
			}
		}
	}
	if len(found) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return found, nil
}

func eduQueries(place Place) []string {
	suffix := eduSiteSuffix(place.Country)
	var queries []string
	if region := strings.TrimSpace(place.Region); region != "" {
		queries = append(queries, fmt.Sprintf("%s university site:%s", region, suffix))
	}
	if city := strings.TrimSpace(place.City); city != "" && !strings.EqualFold(city, place.Region) {
		queries = append(queries, fmt.Sprintf("%s university site:%s", city, suffix))
	}
	if len(queries) == 0 {
		if country := strings.TrimSpace(place.Country); country != "" {
			queries = append(queries, fmt.Sprintf("%s university site:%s", country, suffix))
		}
	}
	if len(queries) > 2 {
		return queries[:2]
	}
	return queries
}

func eduSiteSuffix(country string) string {
	switch strings.ToUpper(strings.TrimSpace(country)) {
	case "CN", "CHN", "CHINA":
		return ".edu.cn"
	case "AU", "AUS", "AUSTRALIA":
		return ".edu.au"
	case "HK", "HKG", "HONG KONG":
		return ".edu.hk"
	case "SG", "SGP", "SINGAPORE":
		return ".edu.sg"
	case "TW", "TWN", "TAIWAN":
		return ".edu.tw"
	default:
		return ".edu"
	}
}

func fetchSearch(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; PPanelRealityScan/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("education search returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func parseEduDomains(body string) []string {
	decoded, err := url.QueryUnescape(body)
	if err != nil {
		decoded = body
	}
	var out []string
	for _, match := range eduHostPattern.FindAllStringSubmatch(decoded, 200) {
		host := strings.ToLower(strings.TrimSuffix(match[1], "."))
		if eduName(host) && !excludedDomain(host) {
			out = append(out, host)
		}
	}
	return uniqueEdu(out)
}

func uniqueEdu(domains []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}
