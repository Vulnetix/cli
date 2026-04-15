package vulnetix.rules.vnx_sec_005

import rego.v1

metadata := {
	"id": "VNX-SEC-005",
	"name": "GCP API key",
	"description": "A Google Cloud Platform API key (AIza prefix) was found in source code. GCP API keys can be used to access billable services and exfiltrate data.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-SEC-005",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "gcp", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`AIza[0-9A-Za-z\-_]{35}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GCP API key found; restrict the key and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
