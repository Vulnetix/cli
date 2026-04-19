# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_120

import rego.v1

metadata := {
	"id": "VNX-120",
	"name": "Buffer copy without checking size of input",
	"description": "Classic buffer overflow: strcpy, strcat, and gets copy input into a fixed-size buffer without verifying that the input fits. An attacker who controls input length can overwrite adjacent memory, corrupt the stack, and achieve code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-120/",
	"languages": ["c", "cpp"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [120],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory-safety", "buffer-overflow", "classic-overflow", "cwe-120"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_unsafe_copy_functions := {
	"strcpy(",
	"strcat(",
	"gets(",
	"memcpy(",
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
	some fn in _unsafe_copy_functions
	contains(line, fn)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Buffer copy function '%v' used without destination size check; use strlcpy/strlcat (BSD) or strncpy/strncat with explicit size, and prefer snprintf over sprintf", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
