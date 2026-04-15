package vulnetix.rules.vnx_java_013

import rego.v1

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
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xpath-injection", "java", "injection"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`xpath\.(evaluate|compile)\s*\(`, line)
	regex.match(`(getParameter|getHeader|getQuery|request\.)`, line)
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
	regex.match(`xpath\.(evaluate|compile)\s*\(.*\+`, line)
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
