# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_823

import rego.v1

metadata := {
	"id": "VNX-823",
	"name": "Use of Out-of-range Pointer Offset",
	"description": "Detects source patterns associated with CWE-823 (Use of Out-of-range Pointer Offset). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-823/",
	"languages": ["c"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [823],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["oor-pointer-offset", "cwe-823"],
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
	contains(line, "sizeof")
	some _pat in {"p + "}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Pointer offset — verify stays within array",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
