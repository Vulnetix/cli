# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_649

import rego.v1

metadata := {
	"id": "VNX-649",
	"name": "Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking",
	"description": "Detects source patterns associated with CWE-649 (Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-649/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [649],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["relying-integrity", "cwe-649"],
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
	contains(line, "auth")
	contains(line, "token")
	some _pat in {"base64.decode"}
	contains(line, _pat)
	not contains(line, "verify")
	finding := {
		"rule_id": metadata.id,
		"message": "Auth token obfuscated via base64 only — no integrity check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
