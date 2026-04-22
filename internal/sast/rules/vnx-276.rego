# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_276

import rego.v1

metadata := {
	"id": "VNX-276",
	"name": "Incorrect Default Permissions",
	"description": "Detects source patterns associated with CWE-276 (Incorrect Default Permissions). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-276/",
	"languages": ["c", "cpp", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [276],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["default-permissions", "cwe-276"],
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "0777")
	contains(line, "0666")
	some _pat in {"open("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "File opened with world-writable permissions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "chmod")
	some _pat in {"0o777", "0o666", "777", "666"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "File chmod to world-readable/writable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
