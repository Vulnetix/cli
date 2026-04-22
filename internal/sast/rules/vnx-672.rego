# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_672

import rego.v1

metadata := {
	"id": "VNX-672",
	"name": "CWE-672",
	"description": "Detects source patterns associated with CWE-672 (CWE-672). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-672/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [672],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["expired-resource-use", "cwe-672"],
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
	some _ext in {".py", ".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "expired")
	some _pat in {"cache.get"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Using cached value flagged expired",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
