# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_788

import rego.v1

metadata := {
	"id": "VNX-788",
	"name": "Access of Memory Location After End of Buffer",
	"description": "Detects source patterns associated with CWE-788 (Access of Memory Location After End of Buffer). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-788/",
	"languages": ["c"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [788],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["oob-access-after-end", "cwe-788"],
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
	some _pat in {"buf[size]"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Index equals size — OOB access past end of buffer",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
