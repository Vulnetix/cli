# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1173

import rego.v1

metadata := {
	"id": "VNX-1173",
	"name": "Improper Use of Validation Framework",
	"description": "Detects source patterns associated with CWE-1173 (Improper Use of Validation Framework). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1173/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1173],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["improper-use-validation-framework", "cwe-1173"],
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
	endswith(path, ".java")
	content := input.file_contents[path]
	not contains(content, "BindingResult")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"@Valid"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "@Valid without BindingResult — errors may propagate",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
