# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_135

import rego.v1

metadata := {
	"id": "VNX-135",
	"name": "Incorrect Calculation of Multi-Byte String Length",
	"description": "Detects source patterns associated with CWE-135 (Incorrect Calculation of Multi-Byte String Length). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-135/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [135],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["multibyte", "unicode", "cwe-135"],
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "wchar")
	some _pat in {"strlen(", "wcslen("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Multi-byte / wide-char length computation may be incorrect — use mbstowcs-aware counting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
