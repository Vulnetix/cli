package vulnetix.rules.vnx_php_011

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-011",
	"name": "PHP SQL injection via string concatenation",
	"description": "User-controlled input from superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE) is concatenated directly into SQL query strings passed to mysql_query(), mysqli_query(), or pg_query(). This allows attackers to alter query logic, bypass authentication, and exfiltrate or modify data. Use prepared statements with PDO or MySQLi bind_param() instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-011/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["sql-injection", "injection", "php"],
}

# User input reaches the sink either on the same line (a superglobal read
# inline) or one hop away, through a local assigned from a superglobal a few
# lines above. Requiring the same line missed the ordinary two-line shape
#
#     $id = $_GET["id"];
#     mysql_query("SELECT ... " . $id);
#
# which is the form nearly all real PHP SQL injection takes.
_php_source_re := `\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[`

_user_input(lines, i) if regex.match(_php_source_re, lines[i])

_user_input(lines, i) if helpers.has_tainted_var(lines, i, 12, _php_source_re)

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mysql_query\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection: user input concatenated into mysql_query() — use prepared statements with PDO or MySQLi instead",
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mysqli_query\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection: user input concatenated into mysqli_query() — use prepared statements with MySQLi bind_param() instead",
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`pg_query\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL injection: user input concatenated into pg_query() — use pg_query_params() with parameterized queries instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
