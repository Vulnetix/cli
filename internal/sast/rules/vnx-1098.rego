# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1098

import rego.v1

metadata := {
	"id": "VNX-1098",
	"name": "Data Element containing Pointer Item without Proper Copy Control Element",
	"description": "Detects source patterns associated with CWE-1098 (Data Element containing Pointer Item without Proper Copy Control Element). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1098/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1098],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["data-elem-inconsistent-type", "cwe-1098"],
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
	contains(line, "int")
	contains(line, "str")
	some _pat in {"var = "}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Variable reassigned to inconsistent type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
