# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1335

import rego.v1

metadata := {
	"id": "VNX-1335",
	"name": "Incorrect Bitwise Shift of Integer",
	"description": "Detects source patterns associated with CWE-1335 (Incorrect Bitwise Shift of Integer). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1335/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1335],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["incorrect-bitwise-shift", "cwe-1335"],
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
	contains(line, ">> 32")
	some _pat in {" << "}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Bitwise shift may exceed type width — undefined behavior",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
