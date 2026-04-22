# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_466

import rego.v1

metadata := {
	"id": "VNX-466",
	"name": "Return of Pointer Value Outside of Expected Range",
	"description": "Detects source patterns associated with CWE-466 (Return of Pointer Value Outside of Expected Range). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-466/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [466],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["return-of-pointer-outside-range", "cwe-466"],
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
	some _pat in {"return p + "}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Return of offset pointer — may exceed range",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
