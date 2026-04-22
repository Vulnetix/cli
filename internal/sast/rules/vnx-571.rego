# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_571

import rego.v1

metadata := {
	"id": "VNX-571",
	"name": "Expression is Always True",
	"description": "Detects source patterns associated with CWE-571 (Expression is Always True). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-571/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [571],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["always-true", "cwe-571"],
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
	some _ext in {".c", ".cpp", ".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"if (true)", "if (1)", "if true"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Condition is always true — dead code or missing condition",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
