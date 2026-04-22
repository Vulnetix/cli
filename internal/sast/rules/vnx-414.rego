# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_414

import rego.v1

metadata := {
	"id": "VNX-414",
	"name": "Missing Lock Check",
	"description": "Detects source patterns associated with CWE-414 (Missing Lock Check). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-414/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [414],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["missing-lock-check", "cwe-414"],
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "shared")
	some _pat in {"write"}
	contains(line, _pat)
	not contains(line, "lock")
	finding := {
		"rule_id": metadata.id,
		"message": "Shared resource accessed without lock check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
