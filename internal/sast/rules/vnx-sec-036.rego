package vulnetix.rules.vnx_sec_036

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-036",
	"name": "Heroku API key",
	"description": "Reports a Heroku platform API key: a standalone v2 key (HRKU-AA followed by 58 characters), or a legacy UUID-format key assigned to a name that contains heroku and key, token or secret (HEROKU_API_KEY=..., heroku_api_token: ..., ENV['HEROKU_API_KEY'] ||= ...), or sent as a Bearer token on a line that calls api.heroku.com. A bare UUID without that context, placeholder or example UUIDs and test or fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-036/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "heroku", "credentials"],
}

_v2 := `\b(HRKU-AA[0-9A-Za-z_-]{58})(?:[^0-9A-Za-z_-]|$)`

_legacy := `(?i)heroku[a-z0-9_.-]*(?:key|token|secret|pass(?:word)?)["'\]]*\s*(?::=|=>|\|\|=|[:=])\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`

# A Platform API call carries the key as a bearer token beside the host.
_bearer := `\bBearer\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`

_hit(line) := [m[0][1], "v2"] if {
	contains(line, "HRKU-AA")
	m := regex.find_all_string_submatch_n(_v2, line, 1)
	count(m) > 0
}

_hit(line) := [m[0][1], "legacy"] if {
	not contains(line, "HRKU-AA")
	contains(lower(line), "heroku")
	m := regex.find_all_string_submatch_n(_legacy, line, 1)
	count(m) > 0
}

_hit(line) := [m[0][1], "legacy"] if {
	not contains(line, "HRKU-AA")
	contains(line, "api.heroku.com")
	not regex.match(_legacy, line)
	m := regex.find_all_string_submatch_n(_bearer, line, 1)
	count(m) > 0
}

_gate(content) if contains(content, "HRKU-AA")
_gate(content) if contains(content, "heroku")
_gate(content) if contains(content, "Heroku")
_gate(content) if contains(content, "HEROKU")

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	h := _hit(line)
	not secrets.is_example_token(h[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Heroku API key (%s format) found; revoke it with 'heroku authorizations:revoke' and load it from the environment", [h[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
