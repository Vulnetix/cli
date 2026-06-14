package vulnetix.rules.vnx_sec_044

import rego.v1

metadata := {
	"id": "VNX-SEC-044",
	"name": "Microsoft Teams webhook URL",
	"description": "A Microsoft Teams incoming webhook URL (webhook.office.com or outlook.office.com) was found in source code. Webhook URLs grant the ability to post messages to a Teams channel and can be used for phishing or pivoting.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-044/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "teams", "webhook", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`https?://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9-]+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Microsoft Teams webhook URL found; rotate the webhook in your Teams channel configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
