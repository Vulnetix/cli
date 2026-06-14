package vulnetix.rules.vnx_sec_061

import rego.v1

metadata := {
	"id": "VNX-SEC-061",
	"name": "PostgreSQL connection string with credentials",
	"description": "A PostgreSQL connection string containing a username and password was found in source code. Database credentials in source control can be exfiltrated and used to dump sensitive data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-061/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "postgres", "database", "credentials"],
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
	regex.match(`(?i)postgres(ql)?://[a-zA-Z0-9_.-]+:[^@\s/]+@[a-zA-Z0-9_.-]+(:[0-9]+)?(/[a-zA-Z0-9_.-]*)?`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "PostgreSQL connection string with credentials found; rotate the database password and use a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
