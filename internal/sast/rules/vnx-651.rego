# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_651

import rego.v1

metadata := {
	"id": "VNX-651",
	"name": "CWE-651",
	"description": "Detects source patterns associated with CWE-651 (CWE-651). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-651/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [651],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["soap-envelope", "cwe-651"],
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
	some _ext in {".py", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "password")
	some _pat in {"SOAPEnvelope"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Password in SOAP envelope — ensure WS-Security applied",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
