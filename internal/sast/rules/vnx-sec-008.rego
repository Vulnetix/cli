package vulnetix.rules.vnx_sec_008

import rego.v1

metadata := {
	"id": "VNX-SEC-008",
	"name": "Database connection string with credentials",
	"description": "A database connection string with embedded username and password was found. Connection strings with credentials enable unauthorized database access if leaked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-008/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "database", "credentials", "connection-string"],
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
	regex.match(`(postgres(ql)?|mysql|mongodb(\+srv)?|redis|mssql)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._@!#$%^&*()\-]+@[a-zA-Z0-9.\-]+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Database connection string with embedded credentials found; use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
