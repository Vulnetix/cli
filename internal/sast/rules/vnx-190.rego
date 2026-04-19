# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_190

import rego.v1

metadata := {
	"id": "VNX-190",
	"name": "Integer overflow or wraparound",
	"description": "Integer arithmetic used to compute allocation sizes or array indices can overflow silently, producing a smaller-than-expected value and causing heap underallocation or out-of-bounds access. Common patterns include malloc(a * b) in C without overflow guard and new byte[n * m] in Java.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-190/",
	"languages": ["c", "cpp", "java", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [190],
	"capec": ["CAPEC-92"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["integer-overflow", "memory-safety", "cwe-190"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_c_patterns := {
	"malloc(a * b",
	"malloc(len * ",
	"malloc(count * ",
	"malloc(size * ",
	"malloc(num * ",
	"malloc(n * ",
	"calloc(count,",
	"alloca(",
}

_java_patterns := {
	"new byte[",
	"new int[",
	"new long[",
	"new char[",
	"new short[",
}

_go_patterns := {
	"make([]byte,",
	"make([]int,",
	"make([]int64,",
	"make([]uint8,",
}

_is_c_file(path) if endswith(path, ".c")
_is_c_file(path) if endswith(path, ".cpp")
_is_c_file(path) if endswith(path, ".cc")
_is_c_file(path) if endswith(path, ".cxx")
_is_c_file(path) if endswith(path, ".h")
_is_c_file(path) if endswith(path, ".hpp")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_c_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _c_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible integer overflow in allocation size near '%v'; validate that the product does not exceed SIZE_MAX before passing to malloc/calloc", [pattern]),
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _java_patterns
	contains(line, pattern)
	contains(line, "Integer.parseInt(")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible integer overflow: array allocation size derived from Integer.parseInt near '%v'; validate the parsed value is within expected bounds before allocation", [pattern]),
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _go_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible unbounded allocation near '%v'; ensure the size argument is validated against a maximum before calling make to prevent integer overflow or excessive memory consumption", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
