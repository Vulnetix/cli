package vulnetix.rules.vnx_sec_036

import rego.v1

metadata := {
	"id": "VNX-SEC-036",
	"name": "Heroku API key",
	"description": "A Heroku API key or platform API OAuth token was found in source code. Heroku keys grant full account access including the ability to deploy applications, modify add-ons, and read database contents.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-036/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "heroku", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`HRKU-AA[0-9a-zA-Z_-]{58}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Heroku API key (v2) found; revoke the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
