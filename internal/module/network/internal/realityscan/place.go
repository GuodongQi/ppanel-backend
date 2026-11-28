package realityscan

import (
	"math"
	"strings"
)

// Place is the ASN and region of one public address. The scanner compares a
// camouflage target with the selected VLESS server, never with the panel host.
type Place struct {
	ASN       uint
	ASOrg     string
	Country   string
	Region    string
	City      string
	Latitude  float64
	Longitude float64
}

// Locator reads the ASN and region of an IP. A miss returns false.
type Locator func(ip string) (Place, bool)

const nearbyKilometres = 400

// alignsWithServer is the neighbor rule: the address stays in the VLESS
// server's ASN, and in its country and state or a nearby city.
func alignsWithServer(target, server Place) bool {
	if server.ASN != 0 && target.ASN != 0 && server.ASN != target.ASN {
		return false
	}
	if blockedNetwork(target, server) {
		return false
	}
	if server.Country == "" || target.Country == "" {
		return true
	}
	return sameArea(target, server)
}

// sameArea is the .edu fallback rule. The network may differ. The country
// must match, and so must the state, the city, or a nearby location.
func sameArea(target, server Place) bool {
	if server.Country == "" || target.Country == "" || !strings.EqualFold(server.Country, target.Country) {
		return false
	}
	if server.Region != "" && target.Region != "" && strings.EqualFold(server.Region, target.Region) {
		return true
	}
	if server.City != "" && target.City != "" && strings.EqualFold(server.City, target.City) {
		return true
	}
	return nearby(server, target, nearbyKilometres)
}

// blockedNetwork rejects a CDN network other than the VLESS server's own ASN.
// A server that itself sits on a large network can still use its own /24.
func blockedNetwork(target, server Place) bool {
	if !excludedOrg(target.ASOrg) {
		return false
	}
	return server.ASN == 0 || target.ASN != server.ASN
}

func nearby(left, right Place, kilometres float64) bool {
	if (left.Latitude == 0 && left.Longitude == 0) || (right.Latitude == 0 && right.Longitude == 0) {
		return false
	}
	return haversine(left.Latitude, left.Longitude, right.Latitude, right.Longitude) <= kilometres
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const earth = 6371.0
	r := math.Pi / 180
	dLat := (lat2 - lat1) * r
	dLon := (lon2 - lon1) * r
	lat1 *= r
	lat2 *= r
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earth * math.Asin(math.Min(1, math.Sqrt(a)))
}
