# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1025

import rego.v1

metadata := {
	"id": "VNX-1025",
	"name": "Comparison Using Wrong Factors",
	"description": "The code performs a comparison but uses an incorrect or insufficient set of factors to determine equality or ordering. This often occurs when comparing complex objects by reference instead of value, comparing only part of a credential, or using locale-sensitive comparison where a byte-level comparison is required.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1025/",
	"languages": ["java", "python", "node", "go", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1025],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["comparison", "wrong-factors", "equality", "security-check", "cwe-1025"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Java: String comparison with == instead of equals()
_java_string_eq_patterns := {
	"password ==",
	"token ==",
	"secret ==",
	"hash ==",
	"digest ==",
}

# Python: comparing bytes with str or using == for timing-unsafe token comparison
_python_unsafe_compare := {
	"password ==",
	"token ==",
	"secret ==",
	"hmac ==",
	"digest ==",
	"signature ==",
}

# JavaScript: non-strict comparison of security values
_js_unsafe_compare := {
	"password ==",
	"token ==",
	"secret ==",
	"apiKey ==",
	"api_key ==",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_string_eq_patterns
	contains(line, p)
	not contains(line, ".equals(")
	not contains(line, "MessageDigest.isEqual")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java security comparison '%s' uses == on a String; use .equals() for value comparison, or MessageDigest.isEqual() for constant-time comparison of credential hashes", [p]),
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
	some p in _python_unsafe_compare
	contains(line, p)
	not contains(line, "hmac.compare_digest")
	not contains(line, "secrets.compare_digest")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python security comparison '%s' is timing-unsafe; use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison of cryptographic values to prevent timing attacks", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
