package vulnetix.rules.vnx_sec_001

import rego.v1

metadata := {
	"id": "VNX-SEC-001",
	"name": "AWS access key ID",
	"description": "An AWS access key ID (AKIA prefix) was found in source code. Hardcoded cloud credentials enable account takeover and resource abuse.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-001/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "aws", "credentials"],
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
	regex.match(`AKIA[0-9A-Z]{16}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "AWS access key ID found; rotate the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
