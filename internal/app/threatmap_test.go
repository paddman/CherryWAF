package app

import (
	"net/http/httptest"
	"testing"

	"github.com/paddman/CherryWAF/internal/netutil"
)

func TestTrustedRequestGeoAcceptsOnlyTrustedPeer(t *testing.T) {
	trusted, err := netutil.NewTrustedProxies([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest("GET", "https://app.example.test/", nil)
	request.RemoteAddr = "203.0.113.10:43122"
	request.Header.Set("CF-IPCountry", "th")
	request.Header.Set("X-Geo-City", "Bangkok")
	request.Header.Set("X-Geo-Latitude", "13.7563")
	request.Header.Set("X-Geo-Longitude", "100.5018")

	geo := trustedRequestGeo(request, trusted)
	if geo == nil {
		t.Fatal("trustedRequestGeo() = nil, want location")
	}
	if geo.CountryCode != "TH" || geo.City != "Bangkok" {
		t.Fatalf("geo = %#v, want TH/Bangkok", geo)
	}
	if geo.Latitude == nil || geo.Longitude == nil {
		t.Fatalf("coordinates missing: %#v", geo)
	}

	request.RemoteAddr = "198.51.100.25:43122"
	if geo := trustedRequestGeo(request, trusted); geo != nil {
		t.Fatalf("untrusted peer metadata accepted: %#v", geo)
	}
}

func TestTrustedRequestGeoRejectsInvalidCoordinates(t *testing.T) {
	trusted, err := netutil.NewTrustedProxies([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://app.example.test/", nil)
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("CF-IPCountry", "US")
	request.Header.Set("X-Geo-Latitude", "999")
	request.Header.Set("X-Geo-Longitude", "not-a-number")

	geo := trustedRequestGeo(request, trusted)
	if geo == nil || geo.CountryCode != "US" {
		t.Fatalf("geo = %#v, want country-only location", geo)
	}
	if geo.Latitude != nil || geo.Longitude != nil {
		t.Fatalf("invalid coordinates were accepted: %#v", geo)
	}
}
