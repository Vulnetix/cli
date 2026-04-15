package vulnetix.rules.vnx_sec_003

import rego.v1

metadata := {
	"id": "VNX-SEC-003",
	"name": "AWS secret access key",
	"description": "An AWS secret access key was found in source code. Combined with an access key ID, this grants full programmatic access to AWS services.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-SEC-003",
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

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)(aws_secret|secret_access_key|aws_secret_access_key)\s*[=:]\s*['"][0-9a-zA-Z/+]{40}['"]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "AWS secret access key found; rotate the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
