# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_614

import rego.v1

metadata := {
	"id": "VNX-614",
	"name": "CWE-614",
	"description": "Detects source patterns associated with CWE-614 (CWE-614). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-614/",
	"languages": ["node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [614],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["session", "secure-flag", "cwe-614"],
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
	contains(line, "SESSION_COOKIE_SECURE = False")
	finding := {
		"rule_id": metadata.id,
		"message": "Django SESSION_COOKIE_SECURE=False allows cookie over plain HTTP",
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
	contains(line, "cookie")
	some _pat in {"secure: false"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Cookie set with secure:false — transmitted over plain HTTP",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
