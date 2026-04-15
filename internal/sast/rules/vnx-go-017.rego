package vulnetix.rules.vnx_go_017

import rego.v1

metadata := {
	"id": "VNX-GO-017",
	"name": "Go SQL injection via fmt.Sprintf in db.Exec or db.Query",
	"description": "A database/sql query is constructed using fmt.Sprintf or string concatenation before being passed to db.Exec(), db.Query(), db.QueryRow(), or their Context variants. If any interpolated variable is user-controlled, this creates a SQL injection vulnerability.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-017/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["sql-injection", "go"],
}

_is_go(path) if endswith(path, ".go")

_db_methods := {
	"Exec(",
	"ExecContext(",
	"Query(",
	"QueryContext(",
	"QueryRow(",
	"QueryRowContext(",
}

# fmt.Sprintf directly inside a db call
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some method in _db_methods
	contains(line, method)
	contains(line, "fmt.Sprintf")
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query constructed with fmt.Sprintf inside a database call; use parameterised queries with '?' placeholders and pass values as separate arguments to db.Exec/db.Query to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# fmt.Sprintf building a query string that is used in db call nearby
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "fmt.Sprintf")
	regex.match(`(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)`, line)
	not regex.match(`^\s*//`, line)
	window_end := min([count(lines) - 1, i + 6])
	window_lines := array.slice(lines, i + 1, window_end + 1)
	window := concat("\n", window_lines)
	some method in _db_methods
	contains(window, method)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query string built with fmt.Sprintf and then passed to a database method; use parameterised queries with '?' placeholders to prevent SQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
