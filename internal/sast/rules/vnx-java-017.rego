package vulnetix.rules.vnx_java_017

import rego.v1

metadata := {
	"id": "VNX-JAVA-017",
	"name": "Java HTTP response splitting via unsanitised header value",
	"description": "User-controlled input is passed directly to response.addHeader(), response.setHeader(), or response.sendRedirect() without stripping CR (\\r) and LF (\\n) characters. An attacker can inject these characters to split the HTTP response, inject arbitrary headers, or poison caches.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-017/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [113],
	"capec": ["CAPEC-34"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["injection", "crlf", "http", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(addHeader|setHeader)\s*\(`, line)
	regex.match(`getParameter|getHeader|getQueryString|getPathInfo|getAttribute`, line)
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
	contains(line, "sendRedirect")
	regex.match(`getParameter|getHeader|getQueryString|getPathInfo`, line)
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
