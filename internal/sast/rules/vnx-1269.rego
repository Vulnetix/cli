# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1269

import rego.v1

metadata := {
	"id": "VNX-1269",
	"name": "CWE-1269",
	"description": "Detects source patterns associated with CWE-1269 (CWE-1269). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1269/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1269],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["product-released-in-non-release-config", "cwe-1269"],
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
	some _pat in {"pdb.set_trace"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Debug breakpoint left in code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
