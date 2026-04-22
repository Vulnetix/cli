# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_191

import rego.v1

metadata := {
	"id": "VNX-191",
	"name": "Integer Underflow (Wrap or Wraparound)",
	"description": "Detects source patterns associated with CWE-191 (Integer Underflow (Wrap or Wraparound)). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-191/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [191],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["integer-underflow", "arithmetic", "cwe-191"],
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
	some _ext in {".c", ".cpp", ".go", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "- ")
	some _pat in {"unsigned ", "size_t", "uint32_t", "uint64_t"}
	contains(line, _pat)
	not contains(line, "if")
	finding := {
		"rule_id": metadata.id,
		"message": "Subtraction on unsigned integer without underflow check — wraps to very large value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
