package vulnetix.rules.vnx_java_013

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-013",
	"name": "Java XPath injection",
	"description": "Untrusted user input is used to construct an XPath expression via xpath.evaluate() or xpath.compile(). An attacker can manipulate XPath queries to extract unauthorized data or bypass authentication checks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-013/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [643],
	"capec": ["CAPEC-83"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xpath-injection", "java", "injection"],
}

_is_java(path) if endswith(path, ".java")

# Servlet / Spring request accessors that return attacker-controlled text.
_java_source_re := `(getParameter|getHeader|getQueryString|getPathInfo|getCookies|getInputStream|getReader|@RequestParam|@PathVariable|@RequestBody|request\.)`

# Concatenation of a string literal with an expression — the shape of a query
# assembled by hand rather than bound as a parameter.
_concat_re := `["']\s*\+|\+\s*["']`

# The sink and the source are almost never on the same source line. The usual
# shape is three statements: read the parameter, build the expression, then
# evaluate it. _user_input covers the one-hop case (parameter read into a local
# that the sink line names) and _built_by_concat covers the expression that was
# assembled just above the call.
_user_input(lines, i) if regex.match(_java_source_re, lines[i])

_user_input(lines, i) if helpers.has_tainted_var(lines, i, 10, _java_source_re)

_built_by_concat(lines, i) if regex.match(`xpath\.(evaluate|compile)\s*\(.*\+`, lines[i])

_built_by_concat(lines, i) if helpers.has_tainted_var(lines, i, 10, _concat_re)

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`xpath\.(evaluate|compile)\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "XPath expression constructed from user input; use parameterized XPath with variable resolvers or validate input against a strict allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`xpath\.(evaluate|compile)\s*\(`, line)
	_built_by_concat(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "XPath expression constructed with string concatenation; use parameterized XPath queries to prevent XPath injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
