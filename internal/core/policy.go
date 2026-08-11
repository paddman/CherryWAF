package core

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/bot"
	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/ratelimit"
	"github.com/paddman/CherryWAF/internal/waf"
)

type accessPolicy struct {
	allow []netip.Prefix
	deny  []netip.Prefix
}

func newAccessPolicy(allowValues, denyValues []string) (*accessPolicy, error) {
	policy := &accessPolicy{}
	var err error
	policy.allow, err = parsePrefixes(allowValues)
	if err != nil {
		return nil, fmt.Errorf("allow CIDRs: %w", err)
	}
	policy.deny, err = parsePrefixes(denyValues)
	if err != nil {
		return nil, fmt.Errorf("deny CIDRs: %w", err)
	}
	if len(policy.allow) == 0 && len(policy.deny) == 0 {
		return nil, nil
	}
	return policy, nil
}

func (p *accessPolicy) Allowed(value string) (bool, string) {
	if p == nil {
		return true, ""
	}
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return len(p.allow) == 0, "client IP is invalid"
	}
	address = address.Unmap()
	for _, prefix := range p.deny {
		if prefix.Contains(address) {
			return false, "client IP matched application deny list"
		}
	}
	if len(p.allow) == 0 {
		return true, ""
	}
	for _, prefix := range p.allow {
		if prefix.Contains(address) {
			return true, ""
		}
	}
	return false, "client IP is not present in application allow list"
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		address = address.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, bits))
	}
	return prefixes, nil
}

func buildRouteSecurity(cfg *config.Config, vhost config.VirtualHost, globalEngine *waf.Engine, globalLimiter *ratelimit.Limiter) (*waf.Engine, *ratelimit.Limiter, bool, int64, string, *accessPolicy, *bot.Engine, error) {
	policy := vhost.WAFPolicy
	maxBodyBytes := cfg.Security.MaxBodyBytes
	if policy.MaxBodyBytes != 0 {
		maxBodyBytes = policy.MaxBodyBytes
	}

	engine := globalEngine
	needsDedicatedEngine := policy.Mode != "inherit" || policy.BlockThreshold != 0 || policy.Builtins != nil || len(policy.RuleFiles) > 0
	if policy.Mode == "disabled" {
		engine = nil
	} else if needsDedicatedEngine {
		mode := cfg.Security.Mode
		if policy.Mode == "detect" || policy.Mode == "blocking" {
			mode = policy.Mode
		}
		threshold := cfg.Security.BlockThreshold
		if policy.BlockThreshold != 0 {
			threshold = policy.BlockThreshold
		}
		builtins := cfg.Rules.Builtins
		if policy.Builtins != nil {
			builtins = *policy.Builtins
		}
		ruleFiles := make([]string, 0, len(cfg.Rules.Files)+len(policy.RuleFiles))
		for _, path := range append(append([]string(nil), cfg.Rules.Files...), policy.RuleFiles...) {
			ruleFiles = append(ruleFiles, cfg.ResolvePath(path))
		}
		var err error
		engine, err = waf.New(mode, threshold, builtins, ruleFiles)
		if err != nil {
			return nil, nil, false, 0, "", nil, nil, err
		}
	}

	limiter := globalLimiter
	ownLimiter := false
	if policy.RateLimit != nil {
		limiter = nil
		if policy.RateLimit.Enabled {
			limiter = ratelimit.New(
				policy.RateLimit.RequestsPerSecond,
				policy.RateLimit.Burst,
				time.Duration(policy.RateLimit.EntryTTLSeconds)*time.Second,
			)
			ownLimiter = true
		}
	}

	access, err := newAccessPolicy(policy.AllowCIDRs, policy.DenyCIDRs)
	if err != nil {
		if ownLimiter && limiter != nil {
			limiter.Close()
		}
		return nil, nil, false, 0, "", nil, nil, err
	}
	botEngine, err := bot.New(vhost.BotPolicy)
	if err != nil {
		if ownLimiter && limiter != nil {
			limiter.Close()
		}
		return nil, nil, false, 0, "", nil, nil, err
	}
	return engine, limiter, ownLimiter, maxBodyBytes, policy.FailMode, access, botEngine, nil
}
