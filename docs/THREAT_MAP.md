# Global Threat Map

CherryWAF Control Center adds a live global attack map to the **Overview** dashboard.

## Data flow

```text
WAF rule match / block / rate limit
        ↓
SecurityEvent JSONL write
        ↓
In-memory recent-event buffer (latest 512 events)
        ↓
Authenticated WAF status API (latest 200 events)
        ↓
Control Center dashboard, refreshed every 5 seconds
```

The map does not call a browser-side GeoIP service and does not send source IP addresses to a third party.

## Trusted geo metadata

CherryWAF accepts geo metadata only when the directly connected peer matches
`security.trusted_proxies`. Public clients cannot place arbitrary points on the
map by spoofing these headers.

Supported headers, in priority order:

| Field | Headers |
|---|---|
| Country code | `CF-IPCountry`, `X-Geo-Country-Code`, `X-Country-Code` |
| Country name | `X-Geo-Country`, `CF-IPCountry-Name` |
| City | `X-Geo-City`, `CF-IPCity` |
| Latitude | `X-Geo-Latitude`, `CF-IPLatitude` |
| Longitude | `X-Geo-Longitude`, `CF-IPLongitude` |

When only a two-letter country code is available, the browser places the event
at an approximate country center. Explicit latitude and longitude take
precedence.

Example configuration for a trusted reverse proxy:

```json
{
  "security": {
    "trusted_proxies": [
      "10.20.0.0/16"
    ],
    "forwarded_for_header": "X-Forwarded-For"
  }
}
```

The trusted proxy should strip inbound geo headers from public requests and set
its own values after performing GeoIP enrichment.

## Retention and limits

- The WAF retains the latest 512 security events in process memory.
- The status API returns the latest 200 events.
- The map draws at most 48 recent event paths to keep browser rendering bounded.
- The event buffer is intentionally non-persistent and resets when the WAF data
  plane restarts or hot-reloads to a newly built runtime.
- JSONL security logging remains the durable source for SIEM or ClickHouse
  ingestion.
