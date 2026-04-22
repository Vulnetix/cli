# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_913

import rego.v1

metadata := {
	"id": "VNX-913",
	"name": "CWE-913",
	"description": "Detects source patterns associated with CWE-913 (CWE-913). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-913/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [913],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dynamic-code", "cwe-913"],
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
	contains(line, "request")
	some _pat in {"eval(", "exec("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic code execution with request data",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
