package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Engine struct {
	mode           string
	blockThreshold int
	rules          []compiledRule
}

type compiledRule struct {
	rule Rule
	rx   *regexp.Regexp
}

func New(mode string, blockThreshold int, builtins bool, ruleFiles []string) (*Engine, error) {
	if mode != "blocking" && mode != "detect" {
		return nil, fmt.Errorf("invalid WAF mode %q", mode)
	}
	if blockThreshold < 1 {
		return nil, errors.New("block threshold must be greater than zero")
	}

	var rules []Rule
	if builtins {
		rules = append(rules, BuiltinRules()...)
	}
	for _, file := range ruleFiles {
		loaded, err := loadRuleFile(file)
		if err != nil {
			return nil, err
		}
		rules = append(rules, loaded...)
	}

	seen := make(map[string]struct{})
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if _, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		rx, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		compiled = append(compiled, compiledRule{rule: rule, rx: rx})
	}

	sort.SliceStable(compiled, func(i, j int) bool { return compiled[i].rule.ID < compiled[j].rule.ID })
	return &Engine{mode: mode, blockThreshold: blockThreshold, rules: compiled}, nil
}

func (e *Engine) Inspect(data RequestData) Decision {
	if data.Request == nil {
		return Decision{}
	}

	targets := requestTargets(data.Request, data.Body)
	decision := Decision{}

	// Go's HTTP parser rejects most ambiguous framing before a request reaches this
	// point. This catches the remaining dangerous semantic combination.
	if data.Request.ContentLength >= 0 && len(data.Request.TransferEncoding) > 0 {
		decision.Score += 20
		decision.Matches = append(decision.Matches, Match{
			RuleID: "CWAF-000001", RuleName: "Ambiguous request framing",
			Target: "protocol", Severity: "critical", Score: 20, Action: "block",
		})
	}

	for _, compiled := range e.rules {
		for _, target := range compiled.rule.Targets {
			value := targets[target]
			loc := compiled.rx.FindStringIndex(value)
			if loc == nil {
				continue
			}
			if compiled.rule.Action != "log" {
				decision.Score += compiled.rule.Score
			}
			decision.Matches = append(decision.Matches, Match{
				RuleID:   compiled.rule.ID,
				RuleName: compiled.rule.Name,
				Target:   target,
				Severity: compiled.rule.Severity,
				Score:    compiled.rule.Score,
				Action:   compiled.rule.Action,
				Excerpt:  safeExcerpt(value, loc[0], loc[1]),
			})
			break
		}
	}

	shouldBlock := decision.Score >= e.blockThreshold
	for _, match := range decision.Matches {
		if match.Action == "block" {
			shouldBlock = true
			break
		}
	}
	if shouldBlock && e.mode == "blocking" {
		decision.Blocked = true
		if len(decision.Matches) > 0 {
			decision.Reason = decision.Matches[0].RuleName
		} else {
			decision.Reason = "WAF policy"
		}
	}
	return decision
}

func (e *Engine) RuleCount() int { return len(e.rules) }
func (e *Engine) Mode() string   { return e.mode }

func loadRuleFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file %s: %w", path, err)
	}
	var file RuleFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode rule file %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode rule file %s: multiple JSON values are not allowed", path)
		}
		return nil, fmt.Errorf("decode rule file %s: %w", path, err)
	}
	if file.Version != RuleFileVersion {
		return nil, fmt.Errorf("rule file %s uses unsupported version %d", path, file.Version)
	}
	return file.Rules, nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("ID must not be empty")
	}
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("rule %s name must not be empty", rule.ID)
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("rule %s must define at least one target", rule.ID)
	}
	allowedTargets := map[string]bool{"method": true, "path": true, "query": true, "headers": true, "cookies": true, "body": true}
	for _, target := range rule.Targets {
		if !allowedTargets[target] {
			return fmt.Errorf("rule %s uses unsupported target %q", rule.ID, target)
		}
	}
	if len(rule.Pattern) == 0 || len(rule.Pattern) > 8192 {
		return fmt.Errorf("rule %s pattern length must be between 1 and 8192 bytes", rule.ID)
	}
	if rule.Score < 0 || rule.Score > 1000 {
		return fmt.Errorf("rule %s score must be between 0 and 1000", rule.ID)
	}
	if rule.Action != "score" && rule.Action != "block" && rule.Action != "log" {
		return fmt.Errorf("rule %s action must be score, block, or log", rule.ID)
	}
	if rule.Severity == "" {
		return fmt.Errorf("rule %s severity must not be empty", rule.ID)
	}
	return nil
}

func safeExcerpt(value string, start, end int) string {
	const radius = 40
	if start > radius {
		start -= radius
	} else {
		start = 0
	}
	if end+radius < len(value) {
		end += radius
	} else {
		end = len(value)
	}
	out := strings.TrimSpace(value[start:end])
	out = strings.ReplaceAll(out, "\n", " ")
	out = strings.ReplaceAll(out, "\r", " ")
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}
