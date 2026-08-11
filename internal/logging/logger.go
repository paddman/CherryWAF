package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/paddman/CherryWAF/internal/waf"
)

const recentSecurityCapacity = 512

type Logger struct {
	access   *jsonLineWriter
	security *jsonLineWriter

	recentMu    sync.RWMutex
	recent      []SecurityEvent
	recentNext  int
	recentCount int
}

type jsonLineWriter struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

type AccessEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id"`
	ClientIP    string    `json:"client_ip"`
	VirtualHost string    `json:"virtual_host"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Protocol    string    `json:"protocol"`
	Status      int       `json:"status"`
	Bytes       int64     `json:"bytes"`
	DurationMS  float64   `json:"duration_ms"`
	Upstream    string    `json:"upstream,omitempty"`
}

type GeoLocation struct {
	CountryCode string   `json:"country_code,omitempty"`
	Country     string   `json:"country,omitempty"`
	City        string   `json:"city,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
	Source      string   `json:"source,omitempty"`
}

type SecurityEvent struct {
	Timestamp   time.Time    `json:"timestamp"`
	RequestID   string       `json:"request_id"`
	ClientIP    string       `json:"client_ip"`
	VirtualHost string       `json:"virtual_host"`
	Host        string       `json:"host"`
	Method      string       `json:"method"`
	Path        string       `json:"path"`
	Action      string       `json:"action"`
	Score       int          `json:"score"`
	Reason      string       `json:"reason,omitempty"`
	Matches     []waf.Match  `json:"matches,omitempty"`
	Geo         *GeoLocation `json:"geo,omitempty"`
}

func New(accessPath, securityPath string) (*Logger, error) {
	access, err := openJSONWriter(accessPath, os.Stdout)
	if err != nil {
		return nil, fmt.Errorf("open access log: %w", err)
	}
	security, err := openJSONWriter(securityPath, os.Stderr)
	if err != nil {
		_ = access.Close()
		return nil, fmt.Errorf("open security log: %w", err)
	}
	return &Logger{
		access: access, security: security,
		recent: make([]SecurityEvent, recentSecurityCapacity),
	}, nil
}

func (l *Logger) Access(event AccessEvent) error {
	if l == nil || l.access == nil {
		return nil
	}
	return l.access.Write(event)
}

func (l *Logger) Security(event SecurityEvent) error {
	if l == nil {
		return nil
	}
	l.rememberSecurity(event)
	if l.security == nil {
		return nil
	}
	return l.security.Write(event)
}

// RecentSecurity returns up to limit events in insertion order. The returned
// events are detached copies so callers cannot mutate the live ring buffer.
func (l *Logger) RecentSecurity(limit int) []SecurityEvent {
	if l == nil {
		return nil
	}
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	if limit <= 0 || limit > l.recentCount {
		limit = l.recentCount
	}
	result := make([]SecurityEvent, 0, limit)
	if limit == 0 {
		return result
	}
	oldest := (l.recentNext - l.recentCount + recentSecurityCapacity) % recentSecurityCapacity
	skip := l.recentCount - limit
	for index := 0; index < limit; index++ {
		position := (oldest + skip + index) % recentSecurityCapacity
		result = append(result, cloneSecurityEvent(l.recent[position]))
	}
	return result
}

func (l *Logger) rememberSecurity(event SecurityEvent) {
	event = cloneSecurityEvent(event)
	l.recentMu.Lock()
	defer l.recentMu.Unlock()

	if len(l.recent) != recentSecurityCapacity {
		l.recent = make([]SecurityEvent, recentSecurityCapacity)
		l.recentNext = 0
		l.recentCount = 0
	}
	l.recent[l.recentNext] = event
	l.recentNext = (l.recentNext + 1) % recentSecurityCapacity
	if l.recentCount < recentSecurityCapacity {
		l.recentCount++
	}
}

func cloneSecurityEvent(event SecurityEvent) SecurityEvent {
	event.Matches = append([]waf.Match(nil), event.Matches...)
	if event.Geo != nil {
		geo := *event.Geo
		if event.Geo.Latitude != nil {
			latitude := *event.Geo.Latitude
			geo.Latitude = &latitude
		}
		if event.Geo.Longitude != nil {
			longitude := *event.Geo.Longitude
			geo.Longitude = &longitude
		}
		event.Geo = &geo
	}
	return event
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return errors.Join(l.access.Close(), l.security.Close())
}

func openJSONWriter(path string, fallback io.Writer) (*jsonLineWriter, error) {
	if path == "" || path == "-" {
		return &jsonLineWriter{writer: fallback}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &jsonLineWriter{writer: file, closer: file}, nil
}

func (w *jsonLineWriter) Write(value any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return json.NewEncoder(w.writer).Encode(value)
}

func (w *jsonLineWriter) Close() error {
	if w == nil || w.closer == nil {
		return nil
	}
	return w.closer.Close()
}
