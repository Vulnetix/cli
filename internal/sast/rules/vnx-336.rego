# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_336

import rego.v1

metadata := {
	"id": "VNX-336",
	"name": "CWE-336",
	"description": "Detects source patterns associated with CWE-336 (CWE-336). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-336/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [336],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["prng", "seed", "cwe-336"],
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
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "Math.random(")
	some _pat in {"token", "password", "session", "id"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Math.random() used for security value — use crypto.randomBytes or crypto.randomUUID",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
