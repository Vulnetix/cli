# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1265

import rego.v1

metadata := {
	"id": "VNX-1265",
	"name": "Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls",
	"description": "Detects source patterns associated with CWE-1265 (Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1265/",
	"languages": ["c"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1265],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["unintended-reentrant", "cwe-1265"],
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
	contains(line, "printf")
	some _pat in {"signal(SIGCHLD"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Non-reentrant function called in reentrant context",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
