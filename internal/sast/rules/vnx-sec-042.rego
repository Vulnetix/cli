package vulnetix.rules.vnx_sec_042

import rego.v1

metadata := {
	"id": "VNX-SEC-042",
	"name": "Slack webhook URL",
	"description": "A Slack incoming webhook URL (hooks.slack.com) was found in source code. Webhook URLs grant the ability to post messages to a Slack channel and can be used for phishing, spam, or pivoting into the workspace.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-042/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "slack", "webhook", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Slack incoming webhook URL found; rotate the webhook in your Slack app settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
