# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1004

import rego.v1

metadata := {
	"id": "VNX-1004",
	"name": "CWE-1004",
	"description": "Detects source patterns associated with CWE-1004 (CWE-1004). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1004/",
	"languages": ["go", "node", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cookie", "httponly", "cwe-1004"],
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "http.Cookie{")
	not contains(line, "HttpOnly: true")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Cookie without HttpOnly: true",
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
	contains(line, "res.cookie(")
	not contains(line, "httpOnly: true")
	finding := {
		"rule_id": metadata.id,
		"message": "res.cookie without httpOnly option",
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
	contains(line, "setcookie(")
	not contains(line, "true,")
	finding := {
		"rule_id": metadata.id,
		"message": "setcookie without httponly flag",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
