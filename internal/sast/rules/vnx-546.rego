# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_546

import rego.v1

metadata := {
	"id": "VNX-546",
	"name": "CWE-546",
	"description": "Detects source patterns associated with CWE-546 (CWE-546). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-546/",
	"languages": ["c", "cpp", "go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [546],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["todo-comment", "cwe-546"],
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
	some _ext in {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"// TODO", "// FIXME", "# TODO", "# FIXME"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "TODO/FIXME comment flags unfinished/unsafe code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
