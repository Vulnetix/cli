# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1046

import rego.v1

metadata := {
	"id": "VNX-1046",
	"name": "Creation of Immutable Text Using String Concatenation",
	"description": "Concatenating strings in loops using the + operator creates many intermediate immutable String objects that persist in the JVM string pool. When concatenation involves sensitive data (passwords, tokens), those values remain in memory far longer than intended, increasing the window for heap dump extraction.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1046/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1046],
	"capec": ["CAPEC-204"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["java", "string-concatenation", "stringbuilder", "memory", "cwe-1046"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Java String concatenation in loops
_loop_start_patterns := {
	"for (",
	"for(",
	"while (",
	"while(",
}

# String concatenation patterns
_string_concat_patterns := {
	" += \"",
	" += '",
	" = \" +",
	" = ' +",
	" + \"",
	"\" + ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some lp in _loop_start_patterns
	contains(line, lp)
	# Check if the next 10 lines contain String concatenation
	some j
	j > i
	j <= i + 10
	j < count(lines)
	some cp in _string_concat_patterns
	contains(lines[j], cp)
	contains(lines[j], "String ")
	not contains(lines[j], "StringBuilder")
	not contains(lines[j], "StringBuffer")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java String concatenation with '%s' inside a loop creates many intermediate immutable String objects; use StringBuilder for loop concatenation to reduce memory pressure and limit how long sensitive values persist in the string pool", [lp]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
