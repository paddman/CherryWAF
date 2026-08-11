package bot

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/ratelimit"
)

type Engine struct {
	mode    string
	bad     []*regexp.Regexp
	allowed []*regexp.Regexp
	limiter *ratelimit.Limiter
}

type Decision struct {
	Matched bool   `json:"matched"`
	Blocked bool   `json:"blocked"`
	Kind    string `json:"kind,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func New(policy config.BotPolicyConfig) (*Engine, error) {
	if !policy.Enabled {
		return nil, nil
	}
	engine := &Engine{mode: policy.Mode}
	var err error
	engine.bad, err = compile(policy.BadUserAgents)
	if err != nil {
		return nil, fmt.Errorf("compile bad user-agent policy: %w", err)
	}
	engine.allowed, err = compile(policy.AllowUserAgents)
	if err != nil {
		return nil, fmt.Errorf("compile allowed user-agent policy: %w", err)
	}
	if policy.RequestsPerMinute > 0 {
		engine.limiter = ratelimit.New(policy.RequestsPerMinute/60, policy.Burst, 10*time.Minute)
	}
	return engine, nil
}

func (e *Engine) Inspect(clientIP, userAgent string) Decision {
	if e == nil {
		return Decision{}
	}
	for _, expression := range e.allowed {
		if expression.MatchString(userAgent) {
			return Decision{}
		}
	}
	for _, expression := range e.bad {
		if expression.MatchString(userAgent) {
			return Decision{
				Matched: true,
				Blocked: e.mode == "block",
				Kind:    "user_agent",
				Reason:  "bot user-agent policy matched",
			}
		}
	}
	if e.limiter != nil && !e.limiter.Allow(strings.TrimSpace(clientIP)) {
		return Decision{
			Matched: true,
			Blocked: e.mode == "block",
			Kind:    "rate",
			Reason:  "bot request-rate policy exceeded",
		}
	}
	return Decision{}
}

func (e *Engine) Close() {
	if e != nil && e.limiter != nil {
		e.limiter.Close()
	}
}

func compile(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		expression, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, expression)
	}
	return compiled, nil
}
