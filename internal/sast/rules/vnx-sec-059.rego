package vulnetix.rules.vnx_sec_059

import rego.v1

metadata := {
	"id": "VNX-SEC-059",
	"name": "Linear API key",
	"description": "A Linear API key (lin_api_ prefix) was found in source code. Linear tokens grant access to issue tracking data including confidential roadmap and customer information.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-059/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "linear", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`lin_api_[a-z0-9]{40}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Linear API key found; revoke the key in the Linear personal settings",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
