# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_453

import rego.v1

metadata := {
	"id": "VNX-453",
	"name": "CWE-453",
	"description": "Detects source patterns associated with CWE-453 (CWE-453). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-453/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [453],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["insecure-default-variable", "cwe-453"],
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
	some _pat in {"def __init__(self, x=[]"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Mutable default argument — shared across calls",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
