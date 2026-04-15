package vulnetix.rules.vnx_ruby_004

import rego.v1

metadata := {
	"id": "VNX-RUBY-004",
	"name": "Ruby SQL injection",
	"description": "Building SQL queries with string interpolation in ActiveRecord where(), find_by_sql(), or execute() is vulnerable to SQL injection.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-004/",
	"languages": ["ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "activerecord", "database"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_sql_indicators := {
	".where(\"",
	".where('",
	"find_by_sql(\"",
	"find_by_sql('",
	".execute(\"SELECT",
	".execute(\"INSERT",
	".execute(\"UPDATE",
	".execute(\"DELETE",
	"connection.execute(\"",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _sql_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string interpolation; use parameterized queries or ActiveRecord sanitization methods",
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
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(where|find_by_sql|execute)\(["'].*#\{`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string interpolation; use parameterized queries or ActiveRecord sanitization methods",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
