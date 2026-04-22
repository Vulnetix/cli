# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_252

import rego.v1

metadata := {
	"id": "VNX-252",
	"name": "Unchecked Return Value",
	"description": "Detects source patterns associated with CWE-252 (Unchecked Return Value). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-252/",
	"languages": ["c", "cpp", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [252],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["error-handling", "unchecked", "cwe-252"],
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "_ = ")
	some _pat in {".Write(", ".Read(", ".Close("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Return value from %s discarded — check for errors", [_pat]),
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
	contains(line, "=")
	some _pat in {"malloc(", "calloc(", "fopen("}
	contains(line, _pat)
	not contains(line, "if ")
	not contains(line, "!= NULL")
	not contains(line, "== NULL")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s return value assigned but never checked for NULL/failure", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
