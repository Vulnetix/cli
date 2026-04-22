# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_394

import rego.v1

metadata := {
	"id": "VNX-394",
	"name": "Unexpected Status Code or Return Value",
	"description": "Detects source patterns associated with CWE-394 (Unexpected Status Code or Return Value). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-394/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [394],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["status-code", "cwe-394"],
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
	some _pat in {"status_code = "}
	contains(line, _pat)
	not contains(line, "200")
	not contains(line, "201")
	not contains(line, "204")
	not contains(line, "400")
	not contains(line, "401")
	not contains(line, "403")
	not contains(line, "404")
	not contains(line, "500")
	finding := {
		"rule_id": metadata.id,
		"message": "Unusual status code returned — verify accurately reflects outcome",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
