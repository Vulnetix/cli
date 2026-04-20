# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_248

import rego.v1

metadata := {
	"id": "VNX-248",
	"name": "Uncaught exception",
	"description": "Checked exceptions that propagate uncaught terminate the program or current thread unexpectedly. In Java, checked exceptions not declared in throws or caught mean a compile-time gap; in Python, unhandled exceptions in main code paths crash the process.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-248/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [248],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["error-handling", "uncaught-exception", "cwe-248"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_java_risky_patterns := {
	"throws RuntimeException",
	"throws Exception",
	"throw new RuntimeException(",
	"throw new Error(",
	"throw new AssertionError(",
}

_python_risky_patterns := {
	"raise Exception(",
	"raise RuntimeError(",
	"raise ValueError(",
	"raise TypeError(",
	"raise KeyError(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _java_risky_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Uncaught exception risk near '%v'; ensure this exception is handled at an appropriate call-stack level, logged, and does not crash the application or leave resources unreleased", [pattern]),
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_risky_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Exception raised near '%v'; verify this exception is caught at an appropriate level or will be surfaced to the user with a meaningful message rather than crashing the process", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
