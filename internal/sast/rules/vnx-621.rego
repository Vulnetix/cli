# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_621

import rego.v1

metadata := {
	"id": "VNX-621",
	"name": "CWE-621",
	"description": "Detects source patterns associated with CWE-621 (CWE-621). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-621/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [621],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["variable-extraction", "cwe-621"],
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"extract("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "PHP extract() converts array to variables — enables variable injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
