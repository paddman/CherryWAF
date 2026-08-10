package netutil

import (
	"fmt"
	"net"
	"strings"
)

type TrustedProxies struct {
	networks []*net.IPNet
}

func NewTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	set := &TrustedProxies{}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy %q: %w", cidr, err)
		}
		set.networks = append(set.networks, network)
	}
	return set, nil
}

func (t *TrustedProxies) Contains(ip net.IP) bool {
	if t == nil || ip == nil {
		return false
	}
	for _, network := range t.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP ignores forwarding headers unless the directly connected peer is
// trusted. When it is trusted, the chain is walked right-to-left and the first
// untrusted address is treated as the client.
func ClientIP(remoteAddr, forwardingHeader string, trusted *TrustedProxies) string {
	remoteIP := parseRemoteIP(remoteAddr)
	if remoteIP == nil {
		return "unknown"
	}
	if !trusted.Contains(remoteIP) || strings.TrimSpace(forwardingHeader) == "" {
		return remoteIP.String()
	}

	parts := strings.Split(forwardingHeader, ",")
	chain := make([]net.IP, 0, len(parts)+1)
	for _, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip != nil {
			chain = append(chain, ip)
		}
	}
	chain = append(chain, remoteIP)
	for i := len(chain) - 1; i >= 0; i-- {
		if !trusted.Contains(chain[i]) {
			return chain[i].String()
		}
	}
	if len(chain) > 0 {
		return chain[0].String()
	}
	return remoteIP.String()
}

func parseRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(remoteAddr, "[]"))
}
