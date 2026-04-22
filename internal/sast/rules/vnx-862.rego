# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_862

import rego.v1

metadata := {
	"id": "VNX-862",
	"name": "CWE-862",
	"description": "Detects source patterns associated with CWE-862 (CWE-862). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-862/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [862],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["missing-authorization", "cwe-862"],
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
	content := input.file_contents[path]
	not contains(content, "require_auth")
	not contains(content, "login_required")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "admin")
	contains(line, "delete")
	some _pat in {"@app.route"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive route without authorization check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
