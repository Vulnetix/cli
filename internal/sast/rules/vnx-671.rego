# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_671

import rego.v1

metadata := {
	"id": "VNX-671",
	"name": "CWE-671",
	"description": "Detects source patterns associated with CWE-671 (CWE-671). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-671/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [671],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["lack-of-administrator-control-over-security", "cwe-671"],
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
	some _ext in {".py", ".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"hidden admin"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Admin control not exposed to administrators",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
