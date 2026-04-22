# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_420

import rego.v1

metadata := {
	"id": "VNX-420",
	"name": "Unprotected Alternate Channel",
	"description": "Detects source patterns associated with CWE-420 (Unprotected Alternate Channel). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-420/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [420],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["unprotected-alternate-channel", "cwe-420"],
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "UNIX")
	some _pat in {"bind("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Unix socket opened — verify permissions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
