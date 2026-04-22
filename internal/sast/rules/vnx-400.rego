# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_400

import rego.v1

metadata := {
	"id": "VNX-400",
	"name": "CWE-400",
	"description": "Detects source patterns associated with CWE-400 (CWE-400). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-400/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["resource-consumption", "cwe-400"],
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
	contains(line, "input")
	some _pat in {"while True:", "while 1:"}
	contains(line, _pat)
	not contains(line, "break")
	finding := {
		"rule_id": metadata.id,
		"message": "Infinite loop over user input without break condition — DoS risk",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
