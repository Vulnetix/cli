# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1114

import rego.v1

metadata := {
	"id": "VNX-1114",
	"name": "Inappropriate Whitespace Style",
	"description": "Detects source patterns associated with CWE-1114 (Inappropriate Whitespace Style). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1114/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1114],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["inappropriate-whitespace", "cwe-1114"],
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
	some _pat in {"\t  "}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Mixed tabs and spaces",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
