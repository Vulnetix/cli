# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_943

import rego.v1

metadata := {
	"id": "VNX-943",
	"name": "CWE-943",
	"description": "Detects source patterns associated with CWE-943 (CWE-943). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-943/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [943],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["nosql-injection", "cwe-943"],
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
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "req.")
	some _pat in {".find(", ".findOne(", ".update("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "MongoDB query contains unsanitized request data — NoSQL injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
