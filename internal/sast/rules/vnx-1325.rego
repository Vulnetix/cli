# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1325

import rego.v1

metadata := {
	"id": "VNX-1325",
	"name": "Improperly Controlled Sequential Memory Allocation",
	"description": "Memory allocations are performed in a loop without tracking or limiting the cumulative total size. An attacker who controls the loop iteration count or individual allocation size can cause the total allocation to exhaust available memory, resulting in denial of service or triggering out-of-memory conditions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1325/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1325],
	"capec": ["CAPEC-130"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory", "allocation", "dos", "loop", "cwe-1325"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# C/C++: malloc/calloc/realloc in loop without size tracking
_c_alloc_patterns := {
	"malloc(",
	"calloc(",
	"realloc(",
	"new char[",
	"new int[",
	"new byte[",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _c_alloc_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Memory allocation '%s' detected; if this occurs in a loop driven by user-controlled input, track cumulative allocation size and enforce a total limit to prevent memory exhaustion DoS", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Go: make in loop without size limit
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "make([]")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Go make([]...) allocation detected; if called in a loop with a user-controlled count, cap the total allocation with a maximum size check to prevent memory exhaustion",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: byte[] allocation in loop context
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "new byte[")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": "Java byte[] allocation 'new byte[...]' detected; if the size comes from user input or a loop counter, validate it against a maximum limit before allocation to prevent OutOfMemoryError or DoS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
