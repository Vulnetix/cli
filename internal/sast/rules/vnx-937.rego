# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_937

import rego.v1

metadata := {
	"id": "VNX-937",
	"name": "CWE-937",
	"description": "Detects source patterns associated with CWE-937 (CWE-937). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-937/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [937],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["known-vulnerable-component", "cwe-937"],
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
	endswith(path, ".json")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "\"2.0\"")
	contains(line, "\"2.1\"")
	some _pat in {"\"log4j\""}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Old vulnerable log4j version",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
