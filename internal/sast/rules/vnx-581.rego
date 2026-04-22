# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_581

import rego.v1

metadata := {
	"id": "VNX-581",
	"name": "Object Model Violation: Just One of Equals and Hashcode Defined",
	"description": "Detects source patterns associated with CWE-581 (Object Model Violation: Just One of Equals and Hashcode Defined). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-581/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [581],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["equals-hashcode", "cwe-581"],
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
	not contains(content, "hashCode()")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"public boolean equals("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "equals() defined without hashCode() — breaks hash-based collections",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
