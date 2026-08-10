package waf

func BuiltinRules() []Rule {
	return []Rule{
		{
			ID: "CWAF-100001", Name: "SQL injection keywords", Enabled: true,
			Targets: []string{"path", "query", "body", "cookies"},
			Pattern: `(?i)(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,80}\bfrom\b|\binformation_schema\b|\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b)`,
			Score:   10, Action: "score", Severity: "critical",
		},
		{
			ID: "CWAF-100002", Name: "SQL injection boolean or comment sequence", Enabled: true,
			Targets: []string{"query", "body", "cookies"},
			Pattern: `(?i)(?:['\"]\s*(?:or|and)\s+['\"]?[0-9a-z_]+['\"]?\s*=\s*['\"]?[0-9a-z_]+|(?:--|#|/\*)\s*$)`,
			Score:   8, Action: "score", Severity: "high",
		},
		{
			ID: "CWAF-100010", Name: "Cross-site scripting payload", Enabled: true,
			Targets: []string{"path", "query", "body", "headers"},
			Pattern: `(?i)(?:<\s*script\b|javascript\s*:|data\s*:\s*text/html|on(?:error|load|click|mouseover|focus)\s*=|<\s*(?:iframe|object|embed|svg)\b)`,
			Score:   10, Action: "score", Severity: "critical",
		},
		{
			ID: "CWAF-100020", Name: "Path traversal", Enabled: true,
			Targets: []string{"path", "query", "body", "cookies"},
			Pattern: `(?:\.\.[/\\]){1,}|(?i)(?:/etc/passwd|/proc/self/environ|windows[/\\]win\.ini)`,
			Score:   10, Action: "score", Severity: "critical",
		},
		{
			ID: "CWAF-100030", Name: "Command injection", Enabled: true,
			Targets: []string{"query", "body", "cookies"},
			Pattern: `(?i)(?:;|\|\||&&|\$\(|` + "`" + `)\s*(?:/bin/)?(?:sh|bash|dash|zsh|cmd(?:\.exe)?|powershell|curl|wget|nc|netcat|python|perl|ruby)\b`,
			Score:   10, Action: "score", Severity: "critical",
		},
		{
			ID: "CWAF-100040", Name: "Server-side template injection", Enabled: true,
			Targets: []string{"query", "body"},
			Pattern: `(?s)(?:\{\{.{0,120}(?:config|class|mro|subclasses|system|popen).{0,120}\}\}|\$\{.{0,120}(?:jndi|runtime|exec).{0,120}\})`,
			Score:   9, Action: "score", Severity: "high",
		},
		{
			ID: "CWAF-100050", Name: "Known vulnerability scanner user agent", Enabled: true,
			Targets: []string{"headers"},
			Pattern: `(?i)\b(?:sqlmap|nikto|acunetix|nessus|nuclei|masscan|gobuster|dirbuster|wpscan|zgrab)\b`,
			Score:   6, Action: "score", Severity: "medium",
		},
		{
			ID: "CWAF-100060", Name: "Sensitive file probe", Enabled: true,
			Targets: []string{"path", "query"},
			Pattern: `(?i)(?:^|/)(?:\.env|\.git/config|wp-config\.php|id_rsa|shadow|passwd|web\.config)(?:$|[/?])`,
			Score:   10, Action: "score", Severity: "high",
		},
	}
}
