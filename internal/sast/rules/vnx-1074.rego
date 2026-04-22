# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1074

import rego.v1

metadata := {
	"id": "VNX-1074",
	"name": "Class with Excessively Deep Inheritance",
	"description": "Detects source patterns associated with CWE-1074 (Class with Excessively Deep Inheritance). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1074/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1074],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["excessive-tree-fan-out", "cwe-1074"],
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"children.add"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Tree children accumulation — verify bound",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
