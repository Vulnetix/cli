# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_385

import rego.v1

metadata := {
	"id": "VNX-385",
	"name": "Covert Timing Channel",
	"description": "Detects source patterns associated with CWE-385 (Covert Timing Channel). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-385/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [385],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["covert-timing", "cwe-385"],
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
	some _ext in {".py", ".java", ".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "password")
	some _pat in {"==", "!="}
	contains(line, _pat)
	not contains(line, "hmac.compare_digest")
	not contains(line, "constantTimeEquals")
	finding := {
		"rule_id": metadata.id,
		"message": "Password comparison uses equality — vulnerable to timing analysis. Use constant-time comparator",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
