package vulnetix.rules.vnx_sec_057

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-057",
	"name": "Grafana API / service account token",
	"description": "Reports a Grafana credential written into a file: a service account token (glsa_ + 32 alphanumerics + _ + 8 hex), a Grafana Cloud access policy token (glc_ followed by the base64 JSON body, glc_eyJ...), or a legacy Grafana API key (the base64 of {\"k\":\", eyJrIjoi..., 70+ characters), each standing alone rather than inside a longer identifier. These grant access to dashboards, datasources, alerting and admin APIs, or push metrics and logs to Grafana Cloud. The snippet is redacted. Not reported: bare prefixes (\"glsa_\", \"glc_\" in a prefix check), placeholder bodies (xxxx, 0000, YOUR_TOKEN), low-entropy bodies, ordinary JWTs (eyJhbGci...), tokens read from the environment, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-057/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "grafana", "monitoring", "credentials"],
}

_patterns := [
	["service account token", `(?:^|[^A-Za-z0-9_])(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[^A-Za-z0-9_]|$)`, 3.5],
	["Grafana Cloud access policy token", `(?:^|[^A-Za-z0-9_])(glc_eyJ[A-Za-z0-9+/]{29,400}={0,3})(?:[^A-Za-z0-9_+/=]|$)`, 3.5],
	["legacy API key", `(?:^|[^A-Za-z0-9_+/])(eyJrIjoi[A-Za-z0-9+/]{70,400}={0,3})(?:[^A-Za-z0-9_+/=]|$)`, 4.0],
]

# Literal prefix checks: far cheaper than an unanchored regex alternation.
_has_prefix(s) if contains(s, "glsa_")

_has_prefix(s) if contains(s, "glc_eyJ")

_has_prefix(s) if contains(s, "eyJrIjoi")

findings contains finding if {
	some path, content in input.file_contents
	_has_prefix(content)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_prefix(line)
	some p in _patterns
	some m in regex.find_all_string_submatch_n(p[1], line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, p[2])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Grafana %s found; revoke it in Grafana (Administration > Service accounts) or the Grafana Cloud portal and load it from a secrets manager", [p[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
