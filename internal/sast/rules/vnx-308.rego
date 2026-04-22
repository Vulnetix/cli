# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_308

import rego.v1

metadata := {
	"id": "VNX-308",
	"name": "Use of Single-factor Authentication",
	"description": "Detects source patterns associated with CWE-308 (Use of Single-factor Authentication). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-308/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [308],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["single-factor", "auth", "cwe-308"],
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
	some _ext in {".py", ".js", ".ts", ".java"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "false")
	contains(line, "disabled")
	some _pat in {"twoFactor", "MFA", "2fa"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "MFA/2FA explicitly disabled in config",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
