# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1058

import rego.v1

metadata := {
	"id": "VNX-1058",
	"name": "Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element",
	"description": "Detects source patterns associated with CWE-1058 (Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1058/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1058],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["multi-thread-non-final-static", "cwe-1058"],
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"static Map"}
	contains(line, _pat)
	not contains(line, "Collections.synchronizedMap")
	finding := {
		"rule_id": metadata.id,
		"message": "Static mutable Map in multi-thread context",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
