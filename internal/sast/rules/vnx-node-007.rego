package vulnetix.rules.vnx_node_007

import rego.v1

metadata := {
	"id": "VNX-NODE-007",
	"name": "Node.js SQL injection",
	"description": "Building SQL queries with string concatenation or template literals using user input in Node.js (mysql, pg, knex, sequelize) is vulnerable to SQL injection.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-007/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "database", "mysql", "postgres"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_sql_indicators := {
	".query(\"SELECT",
	".query('SELECT",
	".query(`SELECT",
	".query(\"INSERT",
	".query(\"UPDATE",
	".query(\"DELETE",
	"query(\"SELECT * FROM \" +",
	"query('SELECT * FROM ' +",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _sql_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string concatenation; use parameterized queries ($1, ?) instead",
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
	regex.match(`\.query\(\x60.*\$\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string concatenation; use parameterized queries ($1, ?) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
