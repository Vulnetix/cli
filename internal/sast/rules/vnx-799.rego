# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_799

import rego.v1

metadata := {
	"id": "VNX-799",
	"name": "CWE-799",
	"description": "Detects source patterns associated with CWE-799 (CWE-799). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-799/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [799],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["improper-control-of-interaction-frequency", "cwe-799"],
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
	some _ext in {".py", ".js", ".ts"}
	endswith(path, _ext)
	content := input.file_contents[path]
	not contains(content, "rate_limit")
	not contains(content, "throttle")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "attempts")
	some _pat in {"login", "auth"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Auth endpoint without interaction-frequency control",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
