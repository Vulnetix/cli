# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_359

import rego.v1

metadata := {
	"id": "VNX-359",
	"name": "Exposure of Private Personal Information to an Unauthorized Actor",
	"description": "Detects source patterns associated with CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-359/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [359],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["pii-exposure", "cwe-359"],
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
	some _ext in {".py", ".js", ".ts", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "log")
	contains(line, "print")
	contains(line, "console")
	some _pat in {"SSN", "social_security", "passport"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PII (%s) logged/printed — do not log personal data", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
