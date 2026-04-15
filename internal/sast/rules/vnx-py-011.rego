package vulnetix.rules.vnx_py_011

import rego.v1

metadata := {
	"id": "VNX-PY-011",
	"name": "Python SQL injection",
	"description": "Raw SQL queries built with string formatting or concatenation in Python (Django raw/extra, SQLAlchemy text/execute, psycopg2/sqlite3 execute with f-strings or format) are vulnerable to SQL injection.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-011/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "django", "sqlalchemy", "database"],
}

_is_py(path) if endswith(path, ".py")

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_sql_injection_indicators := {
	".raw(\"",
	".raw(f\"",
	".raw('",
	".raw(f'",
	".extra(where=[\"",
	".extra(where=['",
	"execute(f\"",
	"execute(f'",
	"execute(\"SELECT",
	"execute(\"INSERT",
	"execute(\"UPDATE",
	"execute(\"DELETE",
	"cursor.execute(\"%s\"",
	"text(f\"",
	"text(f'",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _sql_injection_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string formatting; use parameterized queries instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`execute\(.*(%s|%d|\.format\()`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query built with string formatting; use parameterized queries instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
