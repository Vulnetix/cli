# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_119

import rego.v1

metadata := {
	"id": "VNX-119",
	"name": "Improper restriction of buffer operations",
	"description": "Use of unsafe C/C++ string and I/O functions (strcpy, strcat, sprintf, gets, scanf with %s) that do not enforce buffer boundaries. These functions are a primary cause of classic buffer overflows.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-119/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [119],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory-safety", "buffer-overflow", "cwe-119"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_unsafe_functions := {
	"strcpy(",
	"strcat(",
	"gets(",
	"sprintf(",
	`scanf("%s"`,
	`scanf('%s'`,
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
	some fn in _unsafe_functions
	contains(line, fn)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Unsafe function '%v' used without bounds checking; replace with a size-limited alternative such as strlcpy, strncat, snprintf, or fgets", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
