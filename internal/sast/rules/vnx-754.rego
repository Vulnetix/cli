# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_754

import rego.v1

metadata := {
	"id": "VNX-754",
	"name": "CWE-754",
	"description": "Detects source patterns associated with CWE-754 (CWE-754). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-754/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [754],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["unchecked-conditions", "cwe-754"],
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
	some _pat in {"getResourceAsStream("}
	contains(line, _pat)
	not contains(line, "null")
	finding := {
		"rule_id": metadata.id,
		"message": "getResourceAsStream can return null — check before use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
