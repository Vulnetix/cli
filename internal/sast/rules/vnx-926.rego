# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_926

import rego.v1

metadata := {
	"id": "VNX-926",
	"name": "CWE-926",
	"description": "Detects source patterns associated with CWE-926 (CWE-926). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-926/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [926],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["improper-export-android", "cwe-926"],
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
	endswith(path, ".xml")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "activity")
	contains(line, "service")
	some _pat in {"android:exported=\"true\""}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Android component exported — verify intended for cross-app access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
