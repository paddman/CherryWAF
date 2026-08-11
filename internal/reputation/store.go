package reputation

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/paddman/CherryWAF/internal/config"
)

type Store struct {
	mode    string
	entries []entry
}

type entry struct {
	prefix netip.Prefix
	reason string
}

type Match struct {
	Prefix string `json:"prefix"`
	Reason string `json:"reason"`
	Mode   string `json:"mode"`
}

func Load(cfg *config.Config) (*Store, error) {
	if cfg == nil || !cfg.Security.Reputation.Enabled {
		return nil, nil
	}
	store := &Store{mode: cfg.Security.Reputation.Mode}
	for _, value := range cfg.Security.Reputation.Entries {
		if err := store.add(value, "inline reputation entry"); err != nil {
			return nil, err
		}
	}
	for _, file := range cfg.Security.Reputation.Files {
		path := cfg.ResolvePath(file)
		if err := store.loadFile(path); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(store.entries, func(i, j int) bool {
		return store.entries[i].prefix.Bits() > store.entries[j].prefix.Bits()
	})
	return store, nil
}

func (s *Store) Mode() string {
	if s == nil {
		return "monitor"
	}
	return s.mode
}

func (s *Store) Count() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

func (s *Store) Lookup(value string) (Match, bool) {
	if s == nil {
		return Match{}, false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return Match{}, false
	}
	address = address.Unmap()
	for _, item := range s.entries {
		if item.prefix.Contains(address) {
			return Match{Prefix: item.prefix.String(), Reason: item.reason, Mode: s.mode}, true
		}
	}
	return Match{}, false
}

func (s *Store) loadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open reputation file %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if err := s.add(value, fmt.Sprintf("%s:%d", path, line)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read reputation file %s: %w", path, err)
	}
	return nil
}

func (s *Store) add(value, source string) error {
	value = strings.TrimSpace(value)
	if cut, _, ok := strings.Cut(value, "#"); ok {
		value = strings.TrimSpace(cut)
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil
	}
	prefix, err := parsePrefix(fields[0])
	if err != nil {
		return fmt.Errorf("parse reputation entry %q from %s: %w", value, source, err)
	}
	reason := source
	if len(fields) > 1 {
		reason = strings.Join(fields[1:], " ")
	}
	s.entries = append(s.entries, entry{prefix: prefix, reason: reason})
	return nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	address = address.Unmap()
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address, bits), nil
}
