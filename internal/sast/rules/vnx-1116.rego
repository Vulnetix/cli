# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1116

import rego.v1

metadata := {
	"id": "VNX-1116",
	"name": "Inaccurate Source Code Comments",
	"description": "Detects source patterns associated with CWE-1116 (Inaccurate Source Code Comments). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1116/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1116],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["inaccurate-comments", "cwe-1116"],
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "return ")
	some _pat in {"# Returns None"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Comment may be inaccurate relative to return",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
