package vulnetix.rules.vnx_sec_076

import rego.v1

metadata := {
	"id": "VNX-SEC-076",
	"name": "Telegram bot API token",
	"description": "A Telegram bot API token (numeric-id:alphanumeric-secret format) was found in source code. Telegram bot tokens grant full control of the bot and can be used to read user messages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-076/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "telegram", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[0-9]{5,16}:A[a-z0-9_\-]{34}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Telegram bot API token found; revoke the token via @BotFather",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
