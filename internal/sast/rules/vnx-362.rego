# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_362

import rego.v1

metadata := {
	"id": "VNX-362",
	"name": "CWE-362",
	"description": "Detects source patterns associated with CWE-362 (CWE-362). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-362/",
	"languages": ["go", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [362],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["race-condition", "cwe-362"],
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
	contains(line, "os.open")
	some _pat in {"os.path.exists(", "os.access("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Check-then-use race (TOCTOU): separate exists/open calls allow races; open with O_CREAT|O_EXCL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "os.Stat(")
	some _pat in {"os.Open("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Go stat before open — TOCTOU race",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
