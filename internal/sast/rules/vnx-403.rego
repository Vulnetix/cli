# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_403

import rego.v1

metadata := {
	"id": "VNX-403",
	"name": "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
	"description": "Detects source patterns associated with CWE-403 (Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-403/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [403],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["fd-leak", "cwe-403"],
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	content := input.file_contents[path]
	not contains(content, "close_on_exec")
	not contains(content, "FD_CLOEXEC")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"fork("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "fork() without FD_CLOEXEC may leak open file descriptors to child",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
