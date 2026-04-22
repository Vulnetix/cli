# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_578

import rego.v1

metadata := {
	"id": "VNX-578",
	"name": "CWE-578",
	"description": "Detects source patterns associated with CWE-578 (CWE-578). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-578/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [578],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["exe-side-channel", "cwe-578"],
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "error")
	some _pat in {"Runtime.exec"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Runtime.exec error path — check for side-channel (stderr) leaks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
