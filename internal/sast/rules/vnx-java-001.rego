package vulnetix.rules.vnx_java_001

import rego.v1

metadata := {
	"id": "VNX-JAVA-001",
	"name": "Command injection via Runtime.exec()",
	"description": "Runtime.getRuntime().exec() with string concatenation can inject shell commands when the concatenated value is user-controlled.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-JAVA-001",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "dangerous-function"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Runtime.getRuntime().exec(")
	regex.match(`.*\+\s*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Runtime.exec() with string concatenation; use ProcessBuilder with an argument list instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
