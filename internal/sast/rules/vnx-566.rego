# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_566

import rego.v1

metadata := {
	"id": "VNX-566",
	"name": "CWE-566",
	"description": "Detects source patterns associated with CWE-566 (CWE-566). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-566/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [566],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sql-auth-bypass", "cwe-566"],
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
	some _ext in {".py", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "admin")
	contains(line, "role")
	some _pat in {"\"SELECT"}
	contains(line, _pat)
	not contains(line, "?")
	not contains(line, "$1")
	not contains(line, ":1")
	finding := {
		"rule_id": metadata.id,
		"message": "Authorization query built via string concat — SQL allows auth bypass",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
