# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_128

import rego.v1

metadata := {
	"id": "VNX-128",
	"name": "Wrap-around Error",
	"description": "Detects source patterns associated with CWE-128 (Wrap-around Error). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-128/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [128],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["wraparound", "integer", "cwe-128"],
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
	contains(line, "*")
	some _pat in {"malloc(", "calloc(", "realloc("}
	contains(line, _pat)
	not contains(line, "size_t")
	not contains(line, "SIZE_MAX")
	finding := {
		"rule_id": metadata.id,
		"message": "Allocation with multiplication expression can wrap around; use calloc() or check for overflow before allocation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
