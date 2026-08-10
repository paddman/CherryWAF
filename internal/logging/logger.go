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

type Logger struct {
	access   *jsonLineWriter
	security *jsonLineWriter
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

type SecurityEvent struct {
	Timestamp   time.Time   `json:"timestamp"`
	RequestID   string      `json:"request_id"`
	ClientIP    string      `json:"client_ip"`
	VirtualHost string      `json:"virtual_host"`
	Host        string      `json:"host"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Action      string      `json:"action"`
	Score       int         `json:"score"`
	Reason      string      `json:"reason,omitempty"`
	Matches     []waf.Match `json:"matches,omitempty"`
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
	return &Logger{access: access, security: security}, nil
}

func (l *Logger) Access(event AccessEvent) error {
	if l == nil || l.access == nil {
		return nil
	}
	return l.access.Write(event)
}

func (l *Logger) Security(event SecurityEvent) error {
	if l == nil || l.security == nil {
		return nil
	}
	return l.security.Write(event)
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
