package vulnetix.rules.vnx_sec_031

import rego.v1

metadata := {
	"id": "VNX-SEC-031",
	"name": "Mailgun API key hardcoded",
	"description": "A Mailgun API key (key- prefix followed by 32 hex characters) appears hardcoded in source code. This key allows sending email on behalf of your domain, accessing logs, and modifying domain settings. Revoke at app.mailgun.com/settings/api_security and store in environment variables.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-031/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "mailgun", "email", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`key-[0-9a-zA-Z]{32}`, line)
	regex.match(`(?i)(mailgun|mg_api|mg_key)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mailgun API key detected — revoke at app.mailgun.com/settings/api_security and store in environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
