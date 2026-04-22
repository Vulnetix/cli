# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1060

import rego.v1

metadata := {
	"id": "VNX-1060",
	"name": "Excessive Number of Inefficient Server-Side Data Accesses",
	"description": "Detects source patterns associated with CWE-1060 (Excessive Number of Inefficient Server-Side Data Accesses). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1060/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1060],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["inefficient-server-side-access", "cwe-1060"],
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
	contains(line, "cursor.execute")
	some _pat in {"for row in rows"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "N+1 query pattern — batch queries",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
