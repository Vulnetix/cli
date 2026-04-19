# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_416

import rego.v1

metadata := {
	"id": "VNX-416",
	"name": "Use after free",
	"description": "Accessing a pointer after calling free() or delete on it results in undefined behaviour. An attacker who can control heap layout may exploit a use-after-free to achieve code execution, information disclosure, or denial of service.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-416/",
	"languages": ["c", "cpp"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [416],
	"capec": ["CAPEC-416"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory-safety", "use-after-free", "heap", "cwe-416"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_free_patterns := {
	"free(",
	"delete ",
	"delete[]",
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
	some pattern in _free_patterns
	contains(line, pattern)
	not contains(line, "//")
	not contains(line, "* ")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Memory released with '%v'; ensure the pointer is set to NULL immediately after and is not accessed again. Review surrounding code for use-after-free.", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
