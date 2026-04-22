# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_605

import rego.v1

metadata := {
	"id": "VNX-605",
	"name": "Multiple Binds to the Same Port",
	"description": "Detects source patterns associated with CWE-605 (Multiple Binds to the Same Port). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-605/",
	"languages": ["c", "cpp", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [605],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["multiple-binds-same-port", "cwe-605"],
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
	some _ext in {".c", ".cpp", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "SO_REUSEADDR")
	some _pat in {"bind("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "SO_REUSEADDR + bind — verify no race on reuse",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
