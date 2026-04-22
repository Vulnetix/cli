# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_289

import rego.v1

metadata := {
	"id": "VNX-289",
	"name": "Authentication Bypass by Alternate Name",
	"description": "Detects source patterns associated with CWE-289 (Authentication Bypass by Alternate Name). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-289/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [289],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["auth-bypass-alternate-name", "cwe-289"],
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
	contains(line, "admin")
	some _pat in {"toLowerCase()", ".lower()"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Identity compared after case fold — may allow 'Admin', 'AdMin' bypass logic",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
