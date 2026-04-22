# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_178

import rego.v1

metadata := {
	"id": "VNX-178",
	"name": "Improper Handling of Case Sensitivity",
	"description": "Detects source patterns associated with CWE-178 (Improper Handling of Case Sensitivity). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-178/",
	"languages": ["go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [178],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["case-sensitivity", "validation", "cwe-178"],
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
	some _ext in {".java", ".py", ".js", ".ts", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"equals(\"admin\"", "== \"admin\"", "=== \"admin\"", "== 'admin'", "=== 'admin'"}
	contains(line, _pat)
	not contains(line, "toLowerCase")
	not contains(line, "ToLower")
	not contains(line, "lower()")
	finding := {
		"rule_id": metadata.id,
		"message": "Identity/role compared case-sensitively — attackers may bypass check with 'Admin' or 'ADMIN'",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
