# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_204

import rego.v1

metadata := {
	"id": "VNX-204",
	"name": "Observable Response Discrepancy",
	"description": "Detects source patterns associated with CWE-204 (Observable Response Discrepancy). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-204/",
	"languages": ["go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [204],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["timing", "observable-response", "cwe-204"],
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
	some _ext in {".py", ".java", ".go", ".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "return")
	some _pat in {"if user is None", "if (user == null", "if not user"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Authentication branch returns early for missing user — may allow username enumeration via response discrepancy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
