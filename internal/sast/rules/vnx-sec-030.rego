package vulnetix.rules.vnx_sec_030

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-030",
	"name": "Google OAuth client secret hardcoded",
	"description": "Reports a Google OAuth 2.0 client secret: GOCSPX- followed by exactly 28 base64url characters, delimited on both sides, in any file, and a legacy 24-character client_secret value (quoted or unquoted, as in GOOGLE_CLIENT_SECRET=...) in a file that also holds a Google client id (*.apps.googleusercontent.com), such as a downloaded client_secret.json. Placeholders and low-entropy values, the bare GOCSPX- prefix, environment references, client secrets of other providers, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-030/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secret", "google", "oauth", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9_-])(GOCSPX-[A-Za-z0-9_-]{28})(?:[^A-Za-z0-9_-]|$)`

_legacy_re := `(?i)["']?client[_-]?secret["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{24})(?:["'\s,;]|$)`

_candidate(content) if contains(content, "GOCSPX-")

_candidate(content) if {
	contains(content, ".apps.googleusercontent.com")
	regex.match(`(?i)client[_-]?secret`, content)
}

_hit(content, line) if {
	contains(line, "GOCSPX-")
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	token := hit[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(substring(token, 7, -1), 3.5)
}

_hit(content, line) if {
	contains(content, ".apps.googleusercontent.com")
	m := regex.find_all_string_submatch_n(_legacy_re, line, 1)
	count(m) > 0
	token := m[0][1]
	not startswith(token, "GOCSPX")
	regex.match(`[0-9]`, token)
	regex.match(`[A-Za-z]`, token)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	_candidate(content)
	lines := split(content, "\n")
	some i, line in lines
	_hit(content, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Google OAuth client secret detected; rotate at console.cloud.google.com/apis/credentials and store in a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
