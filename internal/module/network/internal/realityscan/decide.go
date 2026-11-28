package realityscan

import (
	"strings"
	"time"

	dto "github.com/perfect-panel/server/internal/module/network/contract"
)

func bestFeasible(results []dto.RealityScanResult) (dto.RealityScanResult, bool) {
	var best dto.RealityScanResult
	found := false
	for _, item := range results {
		if !item.Feasible {
			continue
		}
		if !found || item.Score > best.Score {
			best = item
			found = true
		}
	}
	return best, found
}

func currentScore(results []dto.RealityScanResult, addr string, port int, sni string) (dto.RealityScanResult, bool) {
	var best dto.RealityScanResult
	found := false
	for _, item := range results {
		if !matchesCurrent(item, addr, port, sni) {
			continue
		}
		if !found || item.Score > best.Score {
			best = item
			found = true
		}
	}
	return best, found
}

func matchesCurrent(item dto.RealityScanResult, addr string, port int, sni string) bool {
	addr = strings.TrimSpace(addr)
	sni = strings.TrimSpace(sni)
	if addr == "" {
		addr = sni
	}
	if port == 0 {
		port = 443
	}
	if item.Port != port {
		return false
	}
	if sameHost(item.IP, addr) || sameHost(item.DialHost, addr) || sameHost(item.Origin, addr) {
		return true
	}
	return sni != "" && sameHost(item.CertDomain, sni) && sameHost(addr, sni)
}

func sameHost(left, right string) bool {
	return left != "" && strings.EqualFold(left, right)
}

// decide reports whether best should replace the protocol's current target.
// A dead current target is replaced immediately. A live one stays until best
// clears the score margin and the cooldown has elapsed.
func decide(current dto.RealityScanResult, currentOK bool, best dto.RealityScanResult, margin int, cooledDown bool) (bool, string) {
	if !best.Feasible {
		return false, "no_feasible"
	}
	if currentOK && current.Feasible && matchesCurrent(best, current.DialHost, current.Port, current.CertDomain) {
		return false, "already_best"
	}
	if !currentOK || !current.Feasible {
		return true, "current_down"
	}
	if !cooledDown {
		return false, "cooldown"
	}
	if best.Score < current.Score+margin {
		return false, "margin"
	}
	return true, "higher_score"
}

func cooldownElapsed(lastFinished string, hours int, now time.Time) bool {
	if hours <= 0 || lastFinished == "" {
		return true
	}
	finished, err := time.Parse(time.RFC3339, lastFinished)
	if err != nil {
		return true
	}
	return !now.Before(finished.Add(time.Duration(hours) * time.Hour))
}

func due(cfg dto.RealityScanConfig, report dto.RealityScanReport, now time.Time) bool {
	if !cfg.Enabled || report.Running {
		return false
	}
	clock, err := time.Parse("15:04", cfg.DailyTime)
	if err != nil {
		return false
	}
	scheduled := time.Date(now.Year(), now.Month(), now.Day(), clock.Hour(), clock.Minute(), 0, 0, now.Location())
	if now.Before(scheduled) {
		return false
	}
	today := now.Format("2006-01-02")
	if report.LastCompleted == today || report.LastAttempt == today {
		return false
	}
	return true
}
