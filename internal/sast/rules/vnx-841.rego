# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_841

import rego.v1

metadata := {
	"id": "VNX-841",
	"name": "Improper Enforcement of Behavioral Workflow",
	"description": "Detects source patterns associated with CWE-841 (Improper Enforcement of Behavioral Workflow). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-841/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [841],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["flow-ordering", "cwe-841"],
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
	some _ext in {".py", ".js", ".ts", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"if (paid)", "if paid:"}
	contains(line, _pat)
	not contains(line, "verify")
	not contains(line, "validate")
	finding := {
		"rule_id": metadata.id,
		"message": "Business-flow decision without verification step",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
