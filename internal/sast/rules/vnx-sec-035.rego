package vulnetix.rules.vnx_sec_035

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-035",
	"name": "DigitalOcean personal access token",
	"description": "Reports a DigitalOcean API token: a standalone dop_v1_ personal access token, doo_v1_ OAuth access token or dor_v1_ OAuth refresh token followed by exactly 64 hex characters. Placeholder values and test or fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-035/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "digitalocean", "credentials"],
}

_pattern := `\b(do([por])_v1_[a-f0-9]{64})\b`

_kind := {"p": "personal access token", "o": "OAuth access token", "r": "OAuth refresh token"}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "_v1_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_v1_")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DigitalOcean %s found; revoke the token in the DigitalOcean control panel (API > Tokens) and load it from the environment", [_kind[m[0][2]]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
