package vulnetix.rules.vnx_cs_001

import rego.v1

metadata := {
	"id": "VNX-CS-001",
	"name": "C# SQL injection via string concatenation in SqlCommand",
	"description": "A SQL query is constructed by concatenating or formatting strings with user-supplied input rather than using parameterised queries. An attacker can inject arbitrary SQL through the unsanitised input.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-001/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["sql-injection", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

# Detect new SqlCommand with string concatenation or string.Format/Sprintf
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+(SqlCommand|OleDbCommand|OdbcCommand|OracleCommand)\s*\(`, line)
	regex.match(`\+\s*\w|\bstring\.Format\b|\$"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query constructed with string concatenation or interpolation; use SqlParameter or parameterised queries to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect CommandText assignment with concatenation
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "CommandText")
	regex.match(`=\s*.*\+|\bstring\.Format\b|\$"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "CommandText assigned with string concatenation or interpolation; use SqlParameter or parameterised queries to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
