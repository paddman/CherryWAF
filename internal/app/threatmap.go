package app

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/paddman/CherryWAF/internal/core"
	"github.com/paddman/CherryWAF/internal/logging"
	"github.com/paddman/CherryWAF/internal/netutil"
)

func recentSecurityEvents(runtime *core.Runtime, limit int) []logging.SecurityEvent {
	if runtime == nil || runtime.Logger == nil {
		return nil
	}
	return runtime.Logger.RecentSecurity(limit)
}

// trustedRequestGeo accepts location metadata only from a directly connected
// trusted proxy. This keeps a public client from placing arbitrary points on
// the dashboard by sending spoofed CF-IPCountry or X-Geo-* headers.
func trustedRequestGeo(r *http.Request, trusted *netutil.TrustedProxies) *logging.GeoLocation {
	if r == nil || !trusted.Contains(remoteIP(r.RemoteAddr)) {
		return nil
	}

	countryCode := normalizeCountryCode(firstHeader(r,
		"CF-IPCountry",
		"X-Geo-Country-Code",
		"X-Country-Code",
	))
	country := cleanGeoText(firstHeader(r, "X-Geo-Country", "CF-IPCountry-Name"), 96)
	city := cleanGeoText(firstHeader(r, "X-Geo-City", "CF-IPCity"), 96)
	latitude := parseCoordinate(firstHeader(r, "X-Geo-Latitude", "CF-IPLatitude"), -90, 90)
	longitude := parseCoordinate(firstHeader(r, "X-Geo-Longitude", "CF-IPLongitude"), -180, 180)

	if countryCode == "" && country == "" && city == "" && latitude == nil && longitude == nil {
		return nil
	}
	return &logging.GeoLocation{
		CountryCode: countryCode,
		Country:     country,
		City:        city,
		Latitude:    latitude,
		Longitude:   longitude,
		Source:      "trusted-proxy-header",
	}
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(strings.TrimSpace(remoteAddr), "[]"))
}

func firstHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func normalizeCountryCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return ""
	}
	for _, char := range value {
		if char < 'A' || char > 'Z' {
			return ""
		}
	}
	return value
}

func cleanGeoText(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return -1
		}
		return char
	}, value)
	if limit > 0 {
		runes := []rune(value)
		if len(runes) > limit {
			value = string(runes[:limit])
		}
	}
	return value
}

func parseCoordinate(value string, minimum, maximum float64) *float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	coordinate, err := strconv.ParseFloat(value, 64)
	if err != nil || coordinate < minimum || coordinate > maximum {
		return nil
	}
	return &coordinate
}
