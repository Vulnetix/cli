# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_826

import rego.v1

metadata := {
	"id": "VNX-826",
	"name": "Premature Release of Resource During Expected Lifetime",
	"description": "Detects source patterns associated with CWE-826 (Premature Release of Resource During Expected Lifetime). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-826/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [826],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["premature-release", "cwe-826"],
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
	contains(line, "return")
	some _pat in {"free("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "free() just before return — ensure pointer not dereferenced",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
