package vulnetix.rules.vnx_sec_059

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-059",
	"name": "Linear API key",
	"description": "Reports a Linear credential written into a file: a personal API key (lin_api_ + 40 alphanumerics, either case) or an OAuth access token (lin_oauth_ + 64 hex), standing alone rather than inside a longer identifier. Linear keys read and write issues, projects and comments, including roadmap and customer data. The snippet is redacted. Not reported: bare prefixes in a prefix check, placeholder or low-entropy bodies (xxxx, YOUR_KEY), identifiers that merely begin lin_api_, keys read from the environment, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-059/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "linear", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_])(lin_api_[A-Za-z0-9]{40}|lin_oauth_[a-f0-9]{64})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`lin_(?:api|oauth)_[A-Za-z0-9]`, content)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "lin_")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Linear API key found; revoke the key in Linear (Settings > Security & access) and load it from a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
