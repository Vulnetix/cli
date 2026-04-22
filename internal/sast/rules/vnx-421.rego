# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_421

import rego.v1

metadata := {
	"id": "VNX-421",
	"name": "Race Condition During Access to Alternate Channel",
	"description": "Detects source patterns associated with CWE-421 (Race Condition During Access to Alternate Channel). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-421/",
	"languages": ["c"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [421],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["race-during-alternate-channel", "cwe-421"],
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
	some _pat in {"dup2("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "FD duplication — verify no race between dup and use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
