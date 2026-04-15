package vulnetix.rules.vnx_go_003

import rego.v1

metadata := {
	"id": "VNX-GO-003",
	"name": "SQL injection via fmt.Sprintf",
	"description": "SQL queries built with fmt.Sprintf or string concatenation allow SQL injection when the formatted value is user-controlled. Use parameterized queries with $1 or ? placeholders.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-GO-003",
	"languages": ["go"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "injection", "database"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(Query|QueryRow|Exec|QueryContext|ExecContext)\(.*fmt\.Sprintf`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection via fmt.Sprintf in query; use parameterized queries with placeholder arguments",
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.Raw\(.*fmt\.Sprintf`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection via fmt.Sprintf in GORM Raw query; use parameterized queries",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
