package waf

import "net/http"

const RuleFileVersion = 1

type RuleFile struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Targets     []string `json:"targets"`
	Pattern     string   `json:"pattern"`
	Score       int      `json:"score"`
	Action      string   `json:"action"`
	Severity    string   `json:"severity"`
}

type RequestData struct {
	Request *http.Request
	Body    []byte
}

type Match struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`
	Action   string `json:"action"`
	Excerpt  string `json:"excerpt,omitempty"`
}

type Decision struct {
	Blocked bool    `json:"blocked"`
	Score   int     `json:"score"`
	Reason  string  `json:"reason,omitempty"`
	Matches []Match `json:"matches,omitempty"`
}
