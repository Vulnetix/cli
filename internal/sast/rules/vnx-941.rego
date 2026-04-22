# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_941

import rego.v1

metadata := {
	"id": "VNX-941",
	"name": "Incorrectly Specified Destination in a Communication Channel",
	"description": "Detects source patterns associated with CWE-941 (Incorrectly Specified Destination in a Communication Channel). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-941/",
	"languages": ["go", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [941],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["protocol", "cwe-941"],
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
	some _ext in {".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "auth")
	some _pat in {"udp://"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "UDP used for authenticated flow — consider protocol with integrity",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
