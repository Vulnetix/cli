# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_184

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-184",
	"name": "Incomplete List of Disallowed Inputs",
	"description": "Detects source patterns associated with CWE-184 (Incomplete List of Disallowed Inputs). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-184/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [184],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["denylist", "validation", "cwe-184"],
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
	some _ext in {".py", ".js", ".ts", ".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	regex.match(_denylist_name, line)
	not helpers.is_test_path(path)
	finding := {
		"rule_id": metadata.id,
		"message": "Deny-list based validation found — deny-lists are inherently incomplete, prefer an allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A variable or constant NAMED as a deny-list that is assigned a collection.
# "FORBIDDEN" as an HTTP status, an enum value or a log word is not validation
# by deny-list.
_denylist_name := `(?i)\b(black_?list|deny_?list|block_?list|bad_?(chars|words|patterns|inputs?|extensions?)|forbidden_?(chars|words|patterns|names|extensions?|paths?|inputs?))\w*\s*(:=|=|:)\s*(\[|\{|set\(|new\s|map\[)`
