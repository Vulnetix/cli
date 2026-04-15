package vulnetix.rules.vnx_java_003

import rego.v1

metadata := {
	"id": "VNX-JAVA-003",
	"name": "SQL injection via string concatenation",
	"description": "SQL queries built with string concatenation in JDBC or JPA allow SQL injection when the concatenated value is user-controlled. Use parameterized queries (PreparedStatement) instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-003/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "jdbc", "injection"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_sql_concat_indicators := {
	"createStatement()",
	"executeQuery(\"",
	"executeUpdate(\"",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _sql_concat_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential SQL injection via %s; use PreparedStatement with parameterized queries", [indicator]),
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(jdbcTemplate|entityManager)\.(query|update|execute)\s*\(\s*"[^"]*"\s*\+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection via string concatenation in query; use parameterized queries instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
