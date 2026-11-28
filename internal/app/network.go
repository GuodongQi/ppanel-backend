package app

import (
	"net"
	"time"

	"github.com/perfect-panel/server/internal/infra/geoip"
	"github.com/perfect-panel/server/internal/module/network"
	"github.com/perfect-panel/server/internal/repository"
)

// newNetworkModule wires the network module against the shared store; the
// node/subscribe configuration is runtime-mutable, so the module receives a
// per-request snapshot closure.
func newNetworkModule(store repository.Store, srv *Application) network.Service {
	return network.New(network.Deps{
		Store:    store,
		Logs:     store.Log(),
		Settings: store.System(),
		Location: func() *time.Location {
			location, err := time.LoadLocation(srv.Runtime.Config().AppLocation)
			if err != nil {
				return time.Local
			}
			return location
		},
		TrafficUsage: srv.TrafficUsage,
		Subscription: srv.Subscription,
		Redis:        srv.Redis,
		Config: func() network.Snapshot {
			current := srv.Runtime.Config()
			return network.Snapshot{
				Node:      current.Node,
				Subscribe: current.Subscribe,
			}
		},
		Multiplier: func(at time.Time) float32 {
			manager := srv.Runtime.NodeMultiplierManager()
			if manager == nil {
				return 1
			}
			return manager.GetMultiplier(at)
		},
		// Identity is built before network (see NewApplication).
		Accounts: srv.Identity,
		Places:   geoLocator{geo: srv.GeoIP},
	})
}

// geoLocator answers from the panel's local GeoIP databases. The Reality
// scanner asks it about a VLESS server address and about camouflage targets.
type geoLocator struct {
	geo *geoip.IPLocation
}

func (g geoLocator) Locate(ip net.IP) (network.IPPlace, bool) {
	if g.geo == nil {
		return network.IPPlace{}, false
	}
	found, ok := g.geo.Lookup(ip)
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
