package app

import (
	"context"
	"encoding/json"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/perfect-panel/server/internal/config"
	"github.com/perfect-panel/server/internal/infra/geoip"
	"github.com/perfect-panel/server/internal/module/network"
	dto "github.com/perfect-panel/server/internal/module/network/contract"
	"github.com/perfect-panel/server/pkg/logger"
	"github.com/perfect-panel/server/pkg/requestmeta"
	"gorm.io/gorm"
)

// geoSlot is the process-wide City and ASN database. Saving the Reality scan
// settings can replace it without restarting the panel.
type geoSlot struct {
	mu      sync.RWMutex
	path    string
	current *geoip.IPLocation
	err     string
}

func newGeoSlot(path string, current *geoip.IPLocation) *geoSlot {
	if path == "" {
		path = "./cache/GeoLite2-City.mmdb"
	}
	return &geoSlot{path: path, current: current}
}

func (s *geoSlot) Enrich(metadata requestmeta.Metadata) requestmeta.Metadata {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return requestmeta.Normalize(metadata)
	}
	return current.Enrich(metadata)
}

func (s *geoSlot) CityDB() *geoip2.Reader {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil
	}
	return s.current.DB
}

func (s *geoSlot) Locate(ip net.IP) (network.IPPlace, bool) {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return network.IPPlace{}, false
	}
	found, ok := current.Lookup(ip)
	if !ok {
		return network.IPPlace{}, false
	}
	country := found.CountryCode
	if country == "" {
		country = found.Country
	}
	return network.IPPlace{
		ASN: found.ASN, ASOrg: found.ASOrganization, Country: country, Region: found.Region,
		City: found.City, Latitude: found.Latitude, Longitude: found.Longitude,
	}, true
}

func (s *geoSlot) Status() dto.RealityScanGeoStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := dto.RealityScanGeoStatus{Path: s.path, Error: s.err}
	if s.current == nil {
		return status
	}
	status.Path = s.current.Path
	status.ASNPath = s.current.ASNPath
	status.CityReady = s.current.DB != nil
	status.ASNReady = s.current.ASNDB != nil
	return status
}

func (s *geoSlot) Apply(_ context.Context, cfg dto.RealityScanConfig) (dto.RealityScanGeoStatus, error) {
	if !cfg.GeoIPDownload {
		s.mu.Lock()
		s.err = ""
		s.mu.Unlock()
		return s.Status(), nil
	}
	opened, err := geoip.Open(geoip.Options{
		Path:        s.path,
		Download:    true,
		DownloadURL: cfg.GeoIPCityURL,
		SHA256:      cfg.GeoIPCitySHA256,
		ASNURL:      cfg.GeoIPASNURL,
		ASNSHA256:   cfg.GeoIPASNSHA256,
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.err = err.Error()
		return s.statusLocked(), nil
	}
	old := s.current
	s.current = opened
	s.err = ""
	if opened.ASNDB == nil {
		s.err = "ASN database is unavailable"
	}
	if old != nil && old != opened {
		closeLocation(old)
	}
	return s.statusLocked(), nil
}

func (s *geoSlot) statusLocked() dto.RealityScanGeoStatus {
	status := dto.RealityScanGeoStatus{Path: s.path, Error: s.err}
	if s.current == nil {
		return status
	}
	status.Path = s.current.Path
	status.ASNPath = s.current.ASNPath
	status.CityReady = s.current.DB != nil
	status.ASNReady = s.current.ASNDB != nil
	return status
}

func closeLocation(loc *geoip.IPLocation) {
	if loc == nil {
		return
	}
	if loc.DB != nil {
		_ = loc.DB.Close()
	}
	if loc.ASNDB != nil {
		_ = loc.ASNDB.Close()
	}
}

// openSavedGeoIP downloads the databases when the saved scan settings allow
// it. The container does not keep the files across recreation, so a restart
// has to be able to fetch them again.
func openSavedGeoIP(db *gorm.DB, cfg config.GeoIPConfig) *geoip.IPLocation {
	if db == nil {
		return nil
	}
	var row struct {
		Value string
	}
	err := db.Table("system").Select("value").Where("key = ?", "RealityScannerConfig").Take(&row).Error
	if err != nil || row.Value == "" {
		return nil
	}
	var saved dto.RealityScanConfig
	if json.Unmarshal([]byte(row.Value), &saved) != nil || !saved.GeoIPDownload {
		return nil
	}
	path := cfg.Path
	if path == "" {
		path = "./cache/GeoLite2-City.mmdb"
	}
	opened, err := geoip.Open(geoip.Options{
		Path:        path,
		Download:    true,
		DownloadURL: saved.GeoIPCityURL,
		SHA256:      saved.GeoIPCitySHA256,
		ASNURL:      saved.GeoIPASNURL,
		ASNSHA256:   saved.GeoIPASNSHA256,
	})
	if err != nil {
		logger.Errorw("[GeoIP] saved download failed", logger.Field("path", path), logger.Field("error", err.Error()))
		return nil
	}
	logger.Infof("[GeoIP] opened databases from the saved Reality scan settings")
	return opened
}
