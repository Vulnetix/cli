# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1079

import rego.v1

metadata := {
	"id": "VNX-1079",
	"name": "Parent Class without Virtual Destructor Method",
	"description": "Detects source patterns associated with CWE-1079 (Parent Class without Virtual Destructor Method). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1079/",
	"languages": ["cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1079],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["parent-class-without-virtual-destructor", "cwe-1079"],
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
	endswith(path, ".cpp")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"class Base"}
	contains(line, _pat)
	not contains(line, "virtual ~")
	finding := {
		"rule_id": metadata.id,
		"message": "Base class without virtual destructor",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
