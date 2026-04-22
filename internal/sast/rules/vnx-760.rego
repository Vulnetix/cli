# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_760

import rego.v1

metadata := {
	"id": "VNX-760",
	"name": "CWE-760",
	"description": "Detects source patterns associated with CWE-760 (CWE-760). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-760/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [760],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["password-hash", "predictable-salt", "cwe-760"],
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
	some _ext in {".py", ".java", ".js", ".ts", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"salt = \"", "salt=\"", "SALT = \"", "static final String SALT"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded / predictable salt — salts must be random and per-password",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
