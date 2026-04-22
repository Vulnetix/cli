# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_125

import rego.v1

metadata := {
	"id": "VNX-125",
	"name": "Out-of-bounds Read",
	"description": "Detects source patterns associated with CWE-125 (Out-of-bounds Read). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-125/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [125],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["oob-read", "memory", "cwe-125"],
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
	some _pat in {"strcpy(", "strncpy(", "memcpy(", "memmove(", "strcat(", "strncat("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("C/C++ buffer operation %s is prone to out-of-bounds read if source/size not bounded", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
