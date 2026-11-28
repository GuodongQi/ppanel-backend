package realityscan

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
)

const (
	maxRadius     = 64
	maxSeeds      = 8
	maxCandidates = 30
	maxServers    = 200
	maxTargets    = 2048
	maxSubnets    = 8
	maxResults    = 40
	maxThreads    = 20

	defaultDailyTime     = "04:00"
	defaultPort          = 443
	defaultRadius        = 16
	defaultThreads       = 8
	defaultTimeout       = 5
	defaultMaxCertBytes  = 8192
	defaultScoreMargin   = 400
	defaultCooldownHours = 12
)

var domainPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

// DefaultConfig is the form shown before an administrator saves one.
func DefaultConfig() dto.RealityScanConfig {
	return dto.RealityScanConfig{
		DailyTime:           defaultDailyTime,
		Port:                defaultPort,
		Radius:              defaultRadius,
		ScanServerNeighbors: true,
		Seeds:               []string{},
		Candidates:          []string{},
		AutoSwitch:          false,
		ScoreMargin:         defaultScoreMargin,
		CooldownHours:       defaultCooldownHours,
		ServerIDs:           []int64{},
		Servers:             []dto.RealityScanServer{},
		Threads:             defaultThreads,
		TimeoutSeconds:      defaultTimeout,
		MaxCertBytes:        defaultMaxCertBytes,
	}
}

// Normalize clamps a saved config onto the limits the scanner will run.
func Normalize(cfg dto.RealityScanConfig) (dto.RealityScanConfig, error) {
	cfg.DailyTime = strings.TrimSpace(cfg.DailyTime)
	if cfg.DailyTime == "" {
		cfg.DailyTime = defaultDailyTime
	}
	if _, err := time.Parse("15:04", cfg.DailyTime); err != nil {
		return dto.RealityScanConfig{}, fmt.Errorf("daily_time must be HH:MM")
	}
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return dto.RealityScanConfig{}, fmt.Errorf("port is out of range")
	}
	if cfg.Radius == 0 {
		cfg.Radius = defaultRadius
	}
	if cfg.Radius < 1 || cfg.Radius > maxRadius {
		return dto.RealityScanConfig{}, fmt.Errorf("radius must be from 1 to %d", maxRadius)
	}
	if cfg.Threads == 0 {
		cfg.Threads = defaultThreads
	}
	if cfg.Threads < 1 || cfg.Threads > maxThreads {
		return dto.RealityScanConfig{}, fmt.Errorf("threads must be from 1 to %d", maxThreads)
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = defaultTimeout
	}
	if cfg.TimeoutSeconds < 3 || cfg.TimeoutSeconds > 10 {
		return dto.RealityScanConfig{}, fmt.Errorf("timeout_seconds must be from 3 to 10")
	}
	if cfg.MaxCertBytes == 0 {
		cfg.MaxCertBytes = defaultMaxCertBytes
	}
	if cfg.MaxCertBytes < 1024 || cfg.MaxCertBytes > 32768 {
		return dto.RealityScanConfig{}, fmt.Errorf("max_cert_bytes must be from 1024 to 32768")
	}
	if cfg.ScoreMargin < 0 {
		cfg.ScoreMargin = 0
	}
	if cfg.ScoreMargin > 10000 {
		return dto.RealityScanConfig{}, fmt.Errorf("score_margin must be from 0 to 10000")
	}
	if cfg.CooldownHours == 0 {
		cfg.CooldownHours = defaultCooldownHours
	}
	if cfg.CooldownHours < 1 || cfg.CooldownHours > 168 {
		return dto.RealityScanConfig{}, fmt.Errorf("cooldown_hours must be from 1 to 168")
	}

	seeds, err := cleanHosts(cfg.Seeds, maxSeeds, "seed")
	if err != nil {
		return dto.RealityScanConfig{}, err
	}
	candidates, err := cleanDomains(cfg.Candidates, maxCandidates)
	if err != nil {
		return dto.RealityScanConfig{}, err
	}
	cfg.Seeds = seeds
	cfg.Candidates = candidates
	cfg.ServerIDs = cleanIDs(cfg.ServerIDs)
	servers, err := cleanServers(cfg)
	if err != nil {
		return dto.RealityScanConfig{}, err
	}
	cfg.Servers = servers
	if err := cleanGeoIP(&cfg); err != nil {
		return dto.RealityScanConfig{}, err
	}
	return cfg, nil
}

func cleanGeoIP(cfg *dto.RealityScanConfig) error {
	cfg.GeoIPCityURL = strings.TrimSpace(cfg.GeoIPCityURL)
	cfg.GeoIPASNURL = strings.TrimSpace(cfg.GeoIPASNURL)
	cfg.GeoIPCitySHA256 = strings.ToLower(strings.TrimSpace(cfg.GeoIPCitySHA256))
	cfg.GeoIPASNSHA256 = strings.ToLower(strings.TrimSpace(cfg.GeoIPASNSHA256))
	if err := cleanGeoURL(cfg.GeoIPCityURL, "geoip_city_url"); err != nil {
		return err
	}
	if err := cleanGeoURL(cfg.GeoIPASNURL, "geoip_asn_url"); err != nil {
		return err
	}
	if err := cleanGeoDigest(cfg.GeoIPCitySHA256, "geoip_city_sha256"); err != nil {
		return err
	}
	return cleanGeoDigest(cfg.GeoIPASNSHA256, "geoip_asn_sha256")
}

func cleanGeoURL(value, label string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("%s must be an http(s) URL", label)
	}
	return nil
}

func cleanGeoDigest(value, label string) error {
	if value == "" {
		return nil
	}
	if len(value) != 64 {
		return fmt.Errorf("%s must be a 64-character SHA256 hex digest", label)
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return fmt.Errorf("%s must be a 64-character SHA256 hex digest", label)
		}
	}
	return nil
}

func cleanServers(cfg dto.RealityScanConfig) ([]dto.RealityScanServer, error) {
	servers := cfg.Servers
	if len(servers) == 0 {
		for _, id := range cfg.ServerIDs {
			servers = append(servers, dto.RealityScanServer{
				ServerID: id, Enabled: true, AutoSwitch: cfg.AutoSwitch,
				ScoreMargin: cfg.ScoreMargin, CooldownHours: cfg.CooldownHours,
			})
		}
	}
	seen := map[int64]struct{}{}
	out := make([]dto.RealityScanServer, 0, len(servers))
	for _, item := range servers {
		if item.ServerID <= 0 {
			continue
		}
		if _, ok := seen[item.ServerID]; ok {
			continue
		}
		if item.CooldownHours == 0 {
			item.CooldownHours = cfg.CooldownHours
		}
		if item.CooldownHours < 1 || item.CooldownHours > 168 {
			return nil, fmt.Errorf("cooldown_hours must be from 1 to 168")
		}
		if item.ScoreMargin < 0 || item.ScoreMargin > 10000 {
			return nil, fmt.Errorf("score_margin must be from 0 to 10000")
		}
		seen[item.ServerID] = struct{}{}
		out = append(out, item)
		if len(out) == maxServers {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out, nil
}

func cleanHosts(values []string, limit int, label string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if !validHost(item) {
			return nil, fmt.Errorf("%s %q is not an IP or domain", label, item)
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
		if len(out) > limit {
			return nil, fmt.Errorf("at most %d %ss", limit, label)
		}
	}
	return out, nil
}

func cleanDomains(values []string, limit int) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if !domainPattern.MatchString(item) {
			return nil, fmt.Errorf("candidate %q is not a domain", item)
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
		if len(out) > limit {
			return nil, fmt.Errorf("at most %d candidates", limit)
		}
	}
	return out, nil
}

func cleanIDs(ids []int64) []int64 {
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) == maxServers {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func validHost(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		addr, err := netip.ParseAddr(ip.String())
		return err == nil && addr.Is4()
	}
	return domainPattern.MatchString(value)
}
