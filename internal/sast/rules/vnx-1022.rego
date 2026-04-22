# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1022

import rego.v1

metadata := {
	"id": "VNX-1022",
	"name": "CWE-1022",
	"description": "Detects source patterns associated with CWE-1022 (CWE-1022). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1022/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1022],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["target-blank", "cwe-1022"],
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
	endswith(path, ".html")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"target=\"_blank\""}
	contains(line, _pat)
	not contains(line, "rel=\"noopener")
	finding := {
		"rule_id": metadata.id,
		"message": "_blank link without rel=noopener — tabnabbing risk",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
