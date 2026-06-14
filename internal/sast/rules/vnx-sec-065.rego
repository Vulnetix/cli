package vulnetix.rules.vnx_sec_065

import rego.v1

metadata := {
	"id": "VNX-SEC-065",
	"name": "HTTP basic authentication header",
	"description": "An HTTP Basic authentication header (Authorization: Basic ...) with a base64-encoded credential was found in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-065/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "http", "basic-auth", "credentials"],
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
	regex.match(`(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP Basic authorization header found; rotate the credential and use OAuth/API keys instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
