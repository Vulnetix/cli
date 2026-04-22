# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_523

import rego.v1

metadata := {
	"id": "VNX-523",
	"name": "Unprotected Transport of Credentials",
	"description": "Detects source patterns associated with CWE-523 (Unprotected Transport of Credentials). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-523/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [523],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["unprotected-transport", "cwe-523"],
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
	some _ext in {".py", ".js", ".ts", ".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "login")
	contains(line, "auth")
	some _pat in {"http://"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Auth flow over plain HTTP — force TLS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
