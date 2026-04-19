# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_14

import rego.v1

metadata := {
	"id": "VNX-14",
	"name": "Compiler removal of code to clear buffers (use memset_s or SecureZeroMemory)",
	"description": "Calls to memset() used to clear sensitive buffers before free() or return may be silently removed by optimizing compilers because the write is 'dead'. Use memset_s() or SecureZeroMemory() instead to guarantee the clear is not elided.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-14/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [14],
	"capec": ["CAPEC-204"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["memory", "crypto", "sensitive-data", "c", "cpp"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_c_extensions := {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

_has_c_ext(path) if {
	some ext in _c_extensions
	endswith(path, ext)
}

_unsafe_clear_patterns := {
	"memset(",
	"bzero(",
	"ZeroMemory(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_has_c_ext(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _unsafe_clear_patterns
	contains(line, p)
	not contains(line, "memset_s(")
	not contains(line, "SecureZeroMemory(")
	not contains(line, "explicit_bzero(")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' used to clear a buffer may be optimised away by the compiler; use memset_s() or SecureZeroMemory() to guarantee the clear", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
