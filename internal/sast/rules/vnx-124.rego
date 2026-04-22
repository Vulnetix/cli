# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_124

import rego.v1

metadata := {
	"id": "VNX-124",
	"name": "Buffer Underwrite ('Buffer Underflow')",
	"description": "Detects source patterns associated with CWE-124 (Buffer Underwrite ('Buffer Underflow')). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-124/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [124],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["buffer-underwrite", "memory", "cwe-124"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "-1")
	some _pat in {"memset(", "memcpy("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Buffer operation with negative size/index — potential buffer underwrite",
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"[-1]", "[ -1]"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Array index of -1 writes before buffer start (buffer underwrite)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
