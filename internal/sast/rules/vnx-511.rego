# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_511

import rego.v1

metadata := {
	"id": "VNX-511",
	"name": "CWE-511",
	"description": "Detects source patterns associated with CWE-511 (CWE-511). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-511/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [511],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["logic-time-bomb", "cwe-511"],
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "if")
	contains(line, "2025")
	contains(line, "2026")
	some _pat in {"Date()", "datetime.now()"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded date comparison — verify not a malicious time-bomb",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
