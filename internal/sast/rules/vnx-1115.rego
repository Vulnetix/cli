# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1115

import rego.v1

metadata := {
	"id": "VNX-1115",
	"name": "Source Code Element without Standard Prologue",
	"description": "Detects source patterns associated with CWE-1115 (Source Code Element without Standard Prologue). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1115/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1115],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["missing-prologue", "cwe-1115"],
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
	endswith(path, ".c")
	content := input.file_contents[path]
	not contains(content, "/*")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"#include"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Source file without standard prologue/banner comment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
