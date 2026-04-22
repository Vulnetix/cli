# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_935

import rego.v1

metadata := {
	"id": "VNX-935",
	"name": "CWE-935",
	"description": "Detects source patterns associated with CWE-935 (CWE-935). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-935/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [935],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["third-party-key-mgmt", "cwe-935"],
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
	some _ext in {".c", ".cpp", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "static")
	some _pat in {"encryptWithKey("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Static key used in third-party API",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
