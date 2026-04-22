# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_20

import rego.v1

metadata := {
	"id": "VNX-20",
	"name": "CWE-20",
	"description": "Detects request data flowing to sensitive sinks without an intervening validation call.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-20/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [20],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["input-validation", "cwe-20"],
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
	contains(line, "exec(")
	some _pat in {"request.", "req.body", "req.params", "req.query"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "User request data passed to exec/eval without validation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
