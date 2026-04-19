# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_131

import rego.v1

metadata := {
	"id": "VNX-131",
	"name": "Incorrect calculation of buffer size",
	"description": "malloc(strlen(str)) omits the null terminator byte, allocating one byte too few and causing an off-by-one heap overflow. sizeof(ptr) measures the pointer width, not the object size. Multiplication without overflow checking can wrap on 32-bit targets.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-131/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [131],
	"capec": ["CAPEC-92"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory-safety", "buffer-size", "malloc", "cwe-131"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_bad_size_patterns := {
	"malloc(strlen(",
	"malloc(sizeof(",
	"calloc(sizeof(",
	"realloc(sizeof(",
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
	some pattern in _bad_size_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potentially incorrect buffer size calculation near '%v'; malloc(strlen(s)) needs +1 for null terminator; sizeof(ptr) measures the pointer, not the pointed-to object", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
