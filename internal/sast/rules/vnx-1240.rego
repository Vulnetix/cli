# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1240

import rego.v1

metadata := {
	"id": "VNX-1240",
	"name": "Use of a Cryptographic Primitive with a Risky Implementation",
	"description": "Detects source patterns associated with CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1240/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1240],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["risky-primitive", "cwe-1240"],
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
	some _pat in {"AES/ECB"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "AES/ECB mode used — switch to CBC/GCM",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
