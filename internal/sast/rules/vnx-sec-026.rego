package vulnetix.rules.vnx_sec_026

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-026",
	"name": "DigitalOcean personal access token hardcoded",
	"description": "Reports a DigitalOcean personal access token: dop_v1_ followed by exactly 64 lowercase hex characters, delimited on both sides, in any file. Placeholder and low-entropy values (all zeros, x runs), the bare dop_v1_ prefix or a regular expression for it, and test and fixture paths are not reported. OAuth (doo_v1_) and refresh (dor_v1_) tokens are left to VNX-SEC-035.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-026/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secret", "digitalocean", "cloud", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9_])(dop_v1_[a-f0-9]{64})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, "dop_v1_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "dop_v1_")
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	token := hit[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(substring(token, 7, -1), 3.0)
	finding := {
		"rule_id": metadata.id,
		"message": "DigitalOcean personal access token detected; revoke at cloud.digitalocean.com/account/api/tokens and use environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
