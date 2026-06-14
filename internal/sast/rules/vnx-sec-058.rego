package vulnetix.rules.vnx_sec_058

import rego.v1

metadata := {
	"id": "VNX-SEC-058",
	"name": "Notion API token",
	"description": "A Notion API token (ntn_ prefix) was found in source code. Notion tokens grant access to workspace content which can include sensitive internal documentation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-058/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "notion", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`ntn_[0-9]{11}[A-Za-z0-9]{35}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Notion API token found; revoke the integration in the Notion workspace settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
