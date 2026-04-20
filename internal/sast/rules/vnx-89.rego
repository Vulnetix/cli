# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_89

import rego.v1

metadata := {
	"id": "VNX-89",
	"name": "SQL Injection",
	"description": "User-controlled data is concatenated into a SQL query string. An attacker can break out of the intended query structure and read, modify, or delete arbitrary data in the database, bypass authentication, or execute stored procedures.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-89/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-injection", "injection", "database", "cwe-89"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# SQL keyword fragments that indicate a dynamic query being built
_sql_keywords := {
	"SELECT ",
	"INSERT INTO",
	"UPDATE ",
	"DELETE FROM",
	"DROP TABLE",
	"UNION SELECT",
	"WHERE ",
}

# String concatenation / interpolation indicators
_concat_indicators := {
	" + ",
	" +\t",
	"` ",
	"`+",
	"\"+",
	"'+",
}

# PHP unsafe query functions used with superglobals
_php_unsafe_query_functions := {
	"mysql_query(",
	"mysqli_query(",
	"pg_query(",
	"sqlite_query(",
}

# Ruby ActiveRecord raw query patterns
_ruby_raw_patterns := {
	"find_by_sql(",
	"execute(",
	"where(\"",
	"where('",
	"joins(\"",
	"joins('",
	"select(\"",
	"select('",
}

# Java Statement (not PreparedStatement)
_java_statement_patterns := {
	"Statement stmt",
	"Statement st ",
	"createStatement()",
	".execute(\"",
	".execute('",
	".executeQuery(\"",
	".executeUpdate(\"",
}

# Node.js / Go database query with concatenation
_node_go_query_patterns := {
	"db.query(",
	"db.Query(",
	"db.Exec(",
	"pool.query(",
	"connection.query(",
	"client.query(",
	"knex.raw(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some kw in _sql_keywords
	contains(line, kw)
	some concat in _concat_indicators
	contains(line, concat)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL query containing '%s' is built with string concatenation; use parameterised queries / prepared statements to prevent SQL injection", [kw]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python f-string or %-format with SQL
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some kw in _sql_keywords
	contains(line, kw)
	_has_python_interpolation(line)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python SQL query with '%s' uses string interpolation; use cursor.execute(sql, params) with a parameterised query instead", [kw]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# PHP unsafe query functions with user input
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some fn in _php_unsafe_query_functions
	contains(line, fn)
	_has_php_user_input(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP '%s' called with user input; use PDO or MySQLi with prepared statements and bound parameters", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby ActiveRecord raw query patterns with interpolation
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _ruby_raw_patterns
	contains(line, pattern)
	_has_ruby_interpolation(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Ruby/Rails '%s' with string interpolation is vulnerable to SQL injection; use ActiveRecord parameterised queries (where(column: value) or where('col = ?', val))", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java Statement.execute with string build
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _java_statement_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java '%s' detected; prefer PreparedStatement with parameterised placeholders (?) instead of concatenating user input into the query string", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js / Go query functions with dynamic strings
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some fn in _node_go_query_patterns
	contains(line, fn)
	_has_dynamic_string(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Database query function '%s' called with a dynamic string; use parameterised queries with placeholder values instead", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_python_interpolation(line) if contains(line, "f\"")
_has_python_interpolation(line) if contains(line, "f'")
_has_python_interpolation(line) if contains(line, "% (")
_has_python_interpolation(line) if contains(line, "% self")
_has_python_interpolation(line) if contains(line, ".format(")
_has_python_interpolation(line) if contains(line, "+ ")

_has_php_user_input(line) if contains(line, "$_GET")
_has_php_user_input(line) if contains(line, "$_POST")
_has_php_user_input(line) if contains(line, "$_REQUEST")
_has_php_user_input(line) if contains(line, "$_COOKIE")

_has_ruby_interpolation(line) if contains(line, "#{")
_has_ruby_interpolation(line) if contains(line, "\" +")
_has_ruby_interpolation(line) if contains(line, "' +")

_has_dynamic_string(line) if contains(line, "`")
_has_dynamic_string(line) if contains(line, "+ ")
_has_dynamic_string(line) if contains(line, "${")
_has_dynamic_string(line) if contains(line, "fmt.Sprintf(")
_has_dynamic_string(line) if contains(line, "fmt.Sprintf(")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
