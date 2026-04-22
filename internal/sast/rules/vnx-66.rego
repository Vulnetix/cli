# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_66

import rego.v1

metadata := {
	"id": "VNX-66",
	"name": "Improper Handling of File Names that Identify Virtual Resources",
	"description": "Detects source patterns associated with CWE-66 (Improper Handling of File Names that Identify Virtual Resources). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-66/",
	"languages": ["c", "cpp", "csharp", "go", "java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [66],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["filename", "virtual-resource", "windows", "cwe-66"],
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
	some _ext in {".c", ".cpp", ".cs", ".go", ".java", ".py"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "open")
	some _pat in {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Opening filename looking like a Windows reserved device name (%s) — reserve names cause virtual-resource aliasing", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
