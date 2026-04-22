# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_115

import rego.v1

metadata := {
	"id": "VNX-115",
	"name": "Misinterpretation of Input",
	"description": "Detects source patterns associated with CWE-115 (Misinterpretation of Input). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-115/",
	"languages": ["node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [115],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["misinterpretation", "input", "cwe-115"],
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "request.")
	some _pat in {"int(", "float("}
	contains(line, _pat)
	not contains(line, "try:")
	finding := {
		"rule_id": metadata.id,
		"message": "Python numeric coercion of request data without type-safety guard — misinterpretation risk",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "parseInt(")
	not contains(line, ", 10")
	finding := {
		"rule_id": metadata.id,
		"message": "parseInt() without explicit radix argument can misinterpret input (e.g. '0x' or '08')",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "intval(")
	some _pat in {"$_GET", "$_POST", "$_REQUEST"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "PHP intval on superglobal input — ensure radix explicitly set and size bounded",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
