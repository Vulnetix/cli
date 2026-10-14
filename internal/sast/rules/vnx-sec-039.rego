package vulnetix.rules.vnx_sec_039

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-039",
	"name": "GitLab personal access token (legacy)",
	"description": "Reports a GitLab personal, project or group access token: a standalone glpat- token followed by 20 or more base64url characters (the legacy 20-character form and the longer routable form). Placeholders and test or fixture paths are not reported; other GitLab token types are VNX-SEC-040.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-039/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gitlab", "credentials"],
}

_pattern := `\b(glpat-[A-Za-z0-9_-]{20,}(?:\.[0-9a-z]{2}\.[0-9a-z]{9})?)(?:[^A-Za-z0-9_-]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "glpat-")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "glpat-")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab access token found; revoke it in GitLab (Access tokens settings) and load it from a CI/CD variable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
