package vulnetix.rules.vnx_java_017

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-017",
	"name": "Java HTTP response splitting via unsanitised header value",
	"description": "User-controlled input is passed directly to response.addHeader(), response.setHeader(), or response.sendRedirect() without stripping CR (\\r) and LF (\\n) characters. An attacker can inject these characters to split the HTTP response, inject arbitrary headers, or poison caches.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-017/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [113],
	"capec": ["CAPEC-34"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["injection", "crlf", "http", "java"],
}

_is_java(path) if endswith(path, ".java")

_java_source_re := `getParameter|getHeader|getQueryString|getPathInfo|getAttribute|getCookies|@RequestParam|@PathVariable`

# Reading the parameter and writing the header are separate statements in
# practice; requiring both on one line meant the rule only caught the inlined
# form, which is the rarer of the two.
_user_input(lines, i) if regex.match(_java_source_re, lines[i])

_user_input(lines, i) if helpers.has_tainted_var(lines, i, 10, _java_source_re)

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`(addHeader|setHeader)\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP header value derived from user input; strip \\r and \\n before calling addHeader()/setHeader() to prevent HTTP response splitting",
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
	contains(line, "sendRedirect")
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "sendRedirect() with unsanitised user input; strip CRLF characters to prevent HTTP response splitting / header injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
