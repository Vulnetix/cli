package vulnetix.rules.vnx_sec_046

import rego.v1

metadata := {
	"id": "VNX-SEC-046",
	"name": "Square access token",
	"description": "A Square access token (EAAA or sq0atp- prefix) was found in source code. Square tokens grant access to payments, customer data, and inventory APIs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-046/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "square", "payments", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`EAAA[\w-]{22,60}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Square access token found; revoke the token in the Square developer dashboard",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sq0atp-[\w-]{22,60}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Square OAuth access token found; revoke the token in the Square developer dashboard",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
