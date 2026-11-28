package realityscan

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
	"github.com/perfect-panel/server/internal/module/network/entity/node"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/xerr"
	"github.com/redis/go-redis/v9"
)

const (
	configKey = "RealityScannerConfig"
	reportKey = "RealityScannerReport"
	lockKey   = "reality:scan:lock"
	category  = "reality_scanner"

	lockTTL     = 40 * time.Minute
	runTimeout  = 35 * time.Minute
	staleRunFor = 45 * time.Minute
)

// Settings stores the scanner config and the latest report.
type Settings interface {
	Load(ctx context.Context, key string) (string, bool, error)
	Save(ctx context.Context, key, value string) error
}

// Nodes reads servers and writes a protocol change back when it is still current.
type Nodes interface {
	FilterServerList(ctx context.Context, params *node.FilterParams) (int64, []*node.Server, error)
	UpdateServerProtocolsIfCurrent(ctx context.Context, id int64, current, updated string) (bool, error)
	ClearServerCache(ctx context.Context, serverId int64) error
}

// Deps are the scanner's ports.
type Deps struct {
	Nodes    Nodes
	Settings Settings
	Redis    *redis.Client
	Now      func() time.Time
	Location func() *time.Location
	// Locate reads the ASN and region of an IP. The scanner uses it for the
	// selected VLESS server's address, not for the machine running the panel.
	Locate Locator
	// Resolve and Status are optional test seams. Nil uses DNS and one HTTPS
	// request.
	Resolve resolver
	Status  statusFunc
}

// Service scans Reality camouflage targets and switches the ones that win.
type Service struct {
	deps    Deps
	resolve resolver
	status  statusFunc

	mu      sync.Mutex
	running bool
}

// New returns a scanner over deps.
func New(deps Deps) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Location == nil {
		deps.Location = func() *time.Location { return time.Local }
	}
	resolve := deps.Resolve
	if resolve == nil {
		resolve = defaultResolve
	}
	status := deps.Status
	if status == nil {
		status = defaultStatus
	}
	return &Service{deps: deps, resolve: resolve, status: status}
}

// View returns the saved config and the latest report.
func (s *Service) View(ctx context.Context) (dto.RealityScanView, error) {
	cfg, report, err := s.load(ctx)
	if err != nil {
		return dto.RealityScanView{}, err
	}
	report.Running = s.scanRunning(report)
	return dto.RealityScanView{Config: cfg, Report: report}, nil
}

// Save stores a normalized config.
func (s *Service) Save(ctx context.Context, cfg dto.RealityScanConfig) (dto.RealityScanView, error) {
	normalized, err := Normalize(cfg)
	if err != nil {
		return dto.RealityScanView{}, xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
	}
	if err := s.saveConfig(ctx, normalized); err != nil {
		return dto.RealityScanView{}, err
	}
	return s.View(ctx)
}

// RunScheduled starts today's scan once the configured time has passed.
func (s *Service) RunScheduled(ctx context.Context) error {
	cfg, report, err := s.load(ctx)
	if err != nil {
		return err
	}
	report.Running = s.scanRunning(report)
	if !due(cfg, report, s.now()) {
		return nil
	}
	_, err = s.launch(ctx, cfg)
	return err
}

// RunNow starts a scan without waiting for the daily time.
func (s *Service) RunNow(ctx context.Context) (dto.RealityScanView, error) {
	cfg, _, err := s.load(ctx)
	if err != nil {
		return dto.RealityScanView{}, err
	}
	return s.launch(ctx, cfg)
}

func (s *Service) launch(ctx context.Context, cfg dto.RealityScanConfig) (dto.RealityScanView, error) {
	_, previous, err := s.load(ctx)
	if err != nil {
		return dto.RealityScanView{}, err
	}
	if !s.tryLock(ctx) {
		view, err := s.View(ctx)
		if err != nil {
			return dto.RealityScanView{}, err
		}
		view.Report.Running = true
		return view, nil
	}
	started := s.now()
	report := dto.RealityScanReport{Running: true, StartedAt: started.Format(time.RFC3339)}
	if err := s.saveReport(ctx, report); err != nil {
		s.unlock(ctx)
		return dto.RealityScanView{}, err
	}
	go s.execute(cfg, started, previous.FinishedAt)
	return dto.RealityScanView{Config: cfg, Report: report}, nil
}

func (s *Service) execute(cfg dto.RealityScanConfig, started time.Time, previousFinished string) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	defer s.unlock(ctx)

	report := dto.RealityScanReport{StartedAt: started.Format(time.RFC3339), LastAttempt: s.day(started)}
	servers, err := s.listServers(ctx)
	if err != nil {
		s.finish(ctx, report, err)
		return
	}
	selected := selectServers(servers, cfg.ServerIDs)
	sites := s.vlessSites(ctx, selected)
	items := s.neighborTargets(sites, cfg)
	items = append(items, s.domainTargets(ctx, cfg.Seeds, sites, "seed")...)
	items = append(items, s.domainTargets(ctx, cfg.Candidates, sites, "candidate")...)
	items = append(items, currentTargets(siteServers(sites), cfg.Port)...)
	items, truncated := dedupeTargets(items)
	report.Truncated = truncated
	results := s.probe(ctx, items, cfg)
	if ctx.Err() != nil {
		s.finish(ctx, report, ctx.Err())
		return
	}
	bestBy := map[int64]dto.RealityScanResult{}
	for _, site := range sites {
		if best, ok := firstFit(results, site, s.deps.Locate, "neighbor"); ok {
			bestBy[site.server.Id] = best
			continue
		}
		if best, ok := firstFit(results, site, s.deps.Locate, "candidate"); ok {
			bestBy[site.server.Id] = best
			continue
		}
		if best, ok := firstFit(results, site, s.deps.Locate, "seed"); ok {
			bestBy[site.server.Id] = best
			continue
		}
		if !cfg.ScanServerNeighbors || !site.known || ctx.Err() != nil {
			continue
		}
		edu := eduTargets(ctx, site.place, s.resolve, s.deps.Locate)
		eduResults := s.probe(ctx, edu, cfg)
		results = append(results, eduResults...)
		if best, ok := firstFit(eduResults, site, s.deps.Locate, "edu"); ok {
			bestBy[site.server.Id] = best
		}
	}
	shown := visible(results, sites, s.deps.Locate)
	sort.Slice(shown, func(i, j int) bool { return shown[i].Score > shown[j].Score })
	report.Scanned = len(results)
	report.Feasible = len(shown)
	if len(shown) > maxResults {
		report.Results = shown[:maxResults]
	} else {
		report.Results = shown
	}
	cooled := cooldownElapsed(previousFinished, cfg.CooldownHours, s.now())
	if cfg.AutoSwitch && len(bestBy) > 0 {
		report.Applied = true
		report.Switches = s.apply(ctx, sites, cfg, results, bestBy, cooled)
	}
	s.finish(ctx, report, nil)
}

func (s *Service) probe(ctx context.Context, items []target, cfg dto.RealityScanConfig) []dto.RealityScanResult {
	return probeAll(ctx, items, cfg.Threads, cfg.TimeoutSeconds, cfg.MaxCertBytes, s.resolve, s.status)
}

func (s *Service) finish(ctx context.Context, report dto.RealityScanReport, err error) {
	now := s.now()
	report.Running = false
	report.FinishedAt = now.Format(time.RFC3339)
	report.LastAttempt = s.day(now)
	if err != nil {
		report.Error = err.Error()
		logger.WithContext(ctx).Errorw("[RealityScan] scan failed", logger.Field("error", err.Error()))
	} else {
		report.LastCompleted = s.day(now)
	}
	if saveErr := s.saveReport(context.Background(), report); saveErr != nil {
		logger.WithContext(ctx).Errorw("[RealityScan] save report failed", logger.Field("error", saveErr.Error()))
	}
}

func (s *Service) apply(ctx context.Context, sites []serverSite, cfg dto.RealityScanConfig, results []dto.RealityScanResult, bestBy map[int64]dto.RealityScanResult, cooled bool) []dto.RealityScanSwitch {
	var switches []dto.RealityScanSwitch
	for _, site := range sites {
		server := site.server
		best := bestBy[server.Id]
		protocols, err := server.UnmarshalProtocols()
		if err != nil {
			switches = append(switches, dto.RealityScanSwitch{ServerID: server.Id, ServerName: server.Name, Reason: "unreadable"})
			continue
		}
		currentJSON := server.Protocols
		changed := false
		for index := range protocols {
			protocol := &protocols[index]
			if !isVLESSReality(*protocol) {
				continue
			}
			addr := protocol.RealityServerAddr
			if addr == "" {
				addr = protocol.SNI
			}
			port := protocol.RealityServerPort
			if port == 0 {
				port = cfg.Port
			}
			current, currentOK := currentScore(results, addr, port, protocol.SNI)
			replace, reason := decide(current, currentOK, best, cfg.ScoreMargin, cooled)
			entry := dto.RealityScanSwitch{
				ServerID:   server.Id,
				ServerName: server.Name,
				Protocol:   protocol.Type,
				FromSNI:    protocol.SNI,
				FromAddr:   addr,
				Score:      best.Score,
				Reason:     reason,
			}
			if replace {
				entry.ToSNI = best.CertDomain
				entry.ToAddr = destinationAddress(best)
				entry.ToPort = best.Port
				protocol.SNI = entry.ToSNI
				protocol.RealityServerAddr = entry.ToAddr
				protocol.RealityServerPort = entry.ToPort
				changed = true
			}
			switches = append(switches, entry)
		}
		if !changed {
			continue
		}
		if err := server.MarshalProtocols(protocols); err != nil {
			switches = append(switches, dto.RealityScanSwitch{ServerID: server.Id, ServerName: server.Name, Reason: "store_failed"})
			continue
		}
		ok, err := s.deps.Nodes.UpdateServerProtocolsIfCurrent(ctx, server.Id, currentJSON, server.Protocols)
		if err != nil || !ok {
			for i := range switches {
				if switches[i].ServerID == server.Id && switches[i].ToAddr != "" {
					switches[i].Reason = "conflict"
					switches[i].ToSNI = ""
					switches[i].ToAddr = ""
					switches[i].ToPort = 0
				}
			}
			continue
		}
		if err := s.deps.Nodes.ClearServerCache(ctx, server.Id); err != nil {
			logger.WithContext(ctx).Errorw("[RealityScan] clear server cache failed", logger.Field("server_id", server.Id), logger.Field("error", err.Error()))
		}
	}
	return switches
}

func destinationAddress(best dto.RealityScanResult) string {
	if (best.Source == "candidate" || best.Source == "seed") && domainPattern.MatchString(best.DialHost) {
		return best.DialHost
	}
	if best.IP != "" {
		return best.IP
	}
	return best.DialHost
}

func isReality(protocol node.Protocol) bool {
	if !protocol.Enable || strings.ToLower(strings.TrimSpace(protocol.Security)) != "reality" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(protocol.Type)) {
	case "vless", "vmess", "trojan":
		return true
	default:
		return false
	}
}

func isVLESSReality(protocol node.Protocol) bool {
	return isReality(protocol) && strings.EqualFold(strings.TrimSpace(protocol.Type), "vless")
}

type serverSite struct {
	server *node.Server
	ip     netip.Addr
	place  Place
	known  bool
}

func (s *Service) vlessSites(ctx context.Context, servers []*node.Server) []serverSite {
	out := make([]serverSite, 0, len(servers))
	for _, server := range servers {
		if server == nil || !hasVLESSReality(server) {
			continue
		}
		ip := s.serverIPv4(ctx, server.Address)
		addr, ok := publicIPv4(ip)
		if !ok {
			continue
		}
		site := serverSite{server: server, ip: addr}
		if s.deps.Locate != nil {
			if place, found := s.deps.Locate(addr.String()); found {
				site.place = place
				site.known = true
			}
		}
		out = append(out, site)
	}
	return out
}

func hasVLESSReality(server *node.Server) bool {
	protocols, err := server.UnmarshalProtocols()
	if err != nil {
		return false
	}
	for _, protocol := range protocols {
		if isVLESSReality(protocol) {
			return true
		}
	}
	return false
}

func (s *Service) serverIPv4(ctx context.Context, address string) net.IP {
	address = strings.TrimSpace(address)
	if ip := net.ParseIP(address); ip != nil {
		return ip
	}
	if address == "" || s.resolve == nil {
		return nil
	}
	ips, err := s.resolve(ctx, address)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if _, ok := publicIPv4(ip); ok {
			return ip
		}
	}
	return nil
}

func (s *Service) neighborTargets(sites []serverSite, cfg dto.RealityScanConfig) []target {
	if !cfg.ScanServerNeighbors {
		return nil
	}
	var items []target
	seen := map[netip.Prefix]struct{}{}
	for _, site := range sites {
		prefix, err := site.ip.Prefix(24)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		if len(seen) >= maxSubnets {
			break
		}
		seen[prefix] = struct{}{}
		items = append(items, slash24Targets(net.ParseIP(site.ip.String()), scanPort)...)
	}
	return items
}

func (s *Service) domainTargets(ctx context.Context, names []string, sites []serverSite, source string) []target {
	var out []target
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || net.ParseIP(name) != nil || excludedDomain(name) || s.resolve == nil {
			continue
		}
		ips, err := s.resolve(ctx, name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			addr, ok := publicIPv4(ip)
			if !ok || !domainFits(addr, sites, s.deps.Locate) {
				continue
			}
			out = append(out, target{
				dialHost: addr.String(), serverName: name, origin: name, source: source, port: scanPort,
			})
			break
		}
	}
	return out
}

func domainFits(ip netip.Addr, sites []serverSite, locate Locator) bool {
	for _, site := range sites {
		if same24(net.ParseIP(ip.String()), site.ip) && neighborPlace(ip, site, locate) {
			return true
		}
		if !site.known || locate == nil {
			continue
		}
		place, found := locate(ip.String())
		if found && !blockedNetwork(place, site.place) && sameArea(place, site.place) {
			return true
		}
	}
	return false
}

func neighborPlace(ip netip.Addr, site serverSite, locate Locator) bool {
	if !site.known || locate == nil {
		return true
	}
	place, found := locate(ip.String())
	if !found {
		return true
	}
	return alignsWithServer(place, site.place)
}

func firstFit(results []dto.RealityScanResult, site serverSite, locate Locator, source string) (dto.RealityScanResult, bool) {
	var best dto.RealityScanResult
	found := false
	for _, item := range results {
		if !item.Feasible || item.Source != source || !fitsSite(item, site, locate) {
			continue
		}
		if !found || item.Score > best.Score {
			best = item
			found = true
		}
	}
	return best, found
}

func fitsSite(item dto.RealityScanResult, site serverSite, locate Locator) bool {
	ip := net.ParseIP(item.IP)
	if ip == nil {
		ip = net.ParseIP(item.DialHost)
	}
	addr, ok := publicIPv4(ip)
	if !ok {
		return false
	}
	if same24(ip, site.ip) {
		return neighborPlace(addr, site, locate)
	}
	if item.Source == "neighbor" || item.Source == "current" || item.Source == "server" || item.Source == "seed" {
		return false
	}
	if !site.known || locate == nil {
		return false
	}
	place, found := locate(addr.String())
	return found && !blockedNetwork(place, site.place) && sameArea(place, site.place)
}

func visible(results []dto.RealityScanResult, sites []serverSite, locate Locator) []dto.RealityScanResult {
	out := make([]dto.RealityScanResult, 0, len(results))
	seen := map[string]struct{}{}
	for _, item := range results {
		if !item.Feasible {
			continue
		}
		for _, site := range sites {
			if !fitsSite(item, site, locate) {
				continue
			}
			key := item.DialHost + "|" + item.CertDomain + "|" + item.Source
			if _, ok := seen[key]; ok {
				break
			}
			seen[key] = struct{}{}
			out = append(out, item)
			break
		}
	}
	return out
}

func currentTargets(servers []*node.Server, port int) []target {
	var out []target
	for _, server := range servers {
		protocols, err := server.UnmarshalProtocols()
		if err != nil {
			continue
		}
		for _, protocol := range protocols {
			if !isVLESSReality(protocol) {
				continue
			}
			host := strings.TrimSpace(protocol.RealityServerAddr)
			if host == "" {
				host = strings.TrimSpace(protocol.SNI)
			}
			if host == "" {
				continue
			}
			destPort := protocol.RealityServerPort
			if destPort == 0 {
				destPort = port
			}
			item := target{dialHost: host, origin: host, source: "current", port: destPort}
			if domainPattern.MatchString(host) {
				item.serverName = host
			}
			out = append(out, item)
		}
	}
	return out
}

func siteServers(sites []serverSite) []*node.Server {
	out := make([]*node.Server, 0, len(sites))
	for _, site := range sites {
		out = append(out, site.server)
	}
	return out
}

func selectServers(servers []*node.Server, ids []int64) []*node.Server {
	if len(ids) == 0 {
		return servers
	}
	wanted := map[int64]struct{}{}
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	out := make([]*node.Server, 0, len(ids))
	for _, server := range servers {
		if _, ok := wanted[server.Id]; ok {
			out = append(out, server)
		}
	}
	return out
}

func (s *Service) listServers(ctx context.Context) ([]*node.Server, error) {
	if s.deps.Nodes == nil {
		return nil, xerr.NewErrMsg("reality scanner has no server store")
	}
	var all []*node.Server
	for page := 1; page <= 20; page++ {
		_, batch, err := s.deps.Nodes.FilterServerList(ctx, &node.FilterParams{Page: page, Size: 200})
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 200 {
			break
		}
	}
	return all, nil
}

func (s *Service) load(ctx context.Context) (dto.RealityScanConfig, dto.RealityScanReport, error) {
	cfg := DefaultConfig()
	raw, ok, err := s.loadKey(ctx, configKey)
	if err != nil {
		return dto.RealityScanConfig{}, dto.RealityScanReport{}, err
	}
	if ok && raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return dto.RealityScanConfig{}, dto.RealityScanReport{}, xerr.Wrapf(err, xerr.ERROR, "reality scan config is invalid")
		}
		cfg, err = Normalize(cfg)
		if err != nil {
			return dto.RealityScanConfig{}, dto.RealityScanReport{}, xerr.NewErrCodeMsg(xerr.InvalidParams, err.Error())
		}
	}
	report, err := s.loadReport(ctx)
	if err != nil {
		return dto.RealityScanConfig{}, dto.RealityScanReport{}, err
	}
	return cfg, report, nil
}

func (s *Service) loadReport(ctx context.Context) (dto.RealityScanReport, error) {
	raw, ok, err := s.loadKey(ctx, reportKey)
	if err != nil || !ok || raw == "" {
		return dto.RealityScanReport{}, err
	}
	var report dto.RealityScanReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return dto.RealityScanReport{}, nil
	}
	return report, nil
}

func (s *Service) loadKey(ctx context.Context, key string) (string, bool, error) {
	if s.deps.Settings == nil {
		return "", false, xerr.NewErrMsg("reality scanner settings are unavailable")
	}
	return s.deps.Settings.Load(ctx, key)
}

func (s *Service) saveConfig(ctx context.Context, cfg dto.RealityScanConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.deps.Settings.Save(ctx, configKey, string(data))
}

func (s *Service) saveReport(ctx context.Context, report dto.RealityScanReport) error {
	if report.Results == nil {
		report.Results = []dto.RealityScanResult{}
	}
	if report.Switches == nil {
		report.Switches = []dto.RealityScanSwitch{}
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return s.deps.Settings.Save(ctx, reportKey, string(data))
}

func (s *Service) scanRunning(report dto.RealityScanReport) bool {
	s.mu.Lock()
	local := s.running
	s.mu.Unlock()
	if local {
		return true
	}
	if !report.Running {
		return false
	}
	started, err := time.Parse(time.RFC3339, report.StartedAt)
	if err != nil {
		return false
	}
	return s.now().Sub(started) < staleRunFor
}

func (s *Service) tryLock(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	if s.deps.Redis != nil {
		ok, err := s.deps.Redis.SetNX(ctx, lockKey, "1", lockTTL).Result()
		if err != nil {
			logger.WithContext(ctx).Errorw("[RealityScan] lock failed", logger.Field("error", err.Error()))
			return false
		}
		if !ok {
			return false
		}
	}
	s.running = true
	return true
}

func (s *Service) unlock(ctx context.Context) {
	s.mu.Lock()
	s.running = false
	redis := s.deps.Redis
	s.mu.Unlock()
	if redis != nil {
		_ = redis.Del(ctx, lockKey).Err()
	}
}

func (s *Service) now() time.Time {
	return s.deps.Now().In(s.deps.Location())
}

func (s *Service) day(at time.Time) string {
	return at.In(s.deps.Location()).Format("2006-01-02")
}
