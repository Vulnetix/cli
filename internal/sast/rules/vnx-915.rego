# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_915

import rego.v1

metadata := {
	"id": "VNX-915",
	"name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
	"description": "Detects source patterns associated with CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-915/",
	"languages": ["node", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["mass-assignment", "cwe-915"],
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
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "req.body")
	some _pat in {"Object.assign("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Object.assign merges request body into model — mass-assignment",
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
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"update_attributes("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Rails update_attributes bypasses strong parameters — mass-assignment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
