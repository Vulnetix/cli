# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_428

import rego.v1

metadata := {
	"id": "VNX-428",
	"name": "Unquoted Search Path or Element",
	"description": "Detects source patterns associated with CWE-428 (Unquoted Search Path or Element). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-428/",
	"languages": ["c", "cpp", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [428],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["unquoted-path", "cwe-428"],
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
	some _ext in {".c", ".cpp", ".cs"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "CreateProcess")
	some _pat in {"\"C:\\\\Program Files"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Unquoted path with spaces in CreateProcess — unquoted search path",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
