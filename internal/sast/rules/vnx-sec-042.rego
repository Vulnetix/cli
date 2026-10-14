package vulnetix.rules.vnx_sec_042

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-042",
	"name": "Slack webhook URL",
	"description": "Reports a complete Slack webhook URL written into a file: an incoming webhook (hooks.slack.com/services/T<team>/B<bot>/<24-character secret>) and a Workflow Builder or trigger webhook (hooks.slack.com/workflows/... or /triggers/... ending in a 32-character secret). Anyone holding the URL can post into the channel. The snippet is redacted. Not reported: a URL missing its secret segment, placeholder URLs (T00000000/B00000000/XXXXXXXX..., EXAMPLE), URLs built from the environment, and test, fixture and vendored paths. VNX-SEC-007 and the generated VNX-SEC-727 also report incoming webhook URLs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-042/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "slack", "webhook", "credentials"],
}

_patterns := [
	`hooks\.slack\.com/services/(T[A-Z0-9]{8,12})/B[A-Z0-9]{8,12}/([A-Za-z0-9]{24})(?:[^A-Za-z0-9]|$)`,
	`hooks\.slack\.com/(?:workflows|triggers)/(T[A-Z0-9]{8,12})/(?:[A-Z0-9]{8,12}/)?[0-9]{8,20}/([A-Za-z0-9]{32})(?:[^A-Za-z0-9]|$)`,
]

_match(line) := [team, secret] if {
	some p in _patterns
	m := regex.find_all_string_submatch_n(p, line, 1)
	count(m) > 0
	team := m[0][1]
	secret := m[0][2]
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "hooks.slack.com/")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "hooks.slack.com/")
	[team, secret] := _match(line)
	not secrets.is_example_token(team)
	not secrets.is_example_token(secret)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack webhook URL found; rotate the webhook in your Slack app settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
