# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_354

import rego.v1

metadata := {
	"id": "VNX-354",
	"name": "Improper Validation of Integrity Check Value",
	"description": "Detects source patterns associated with CWE-354 (Improper Validation of Integrity Check Value). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-354/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [354],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["integrity-validation", "cwe-354"],
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
	some _pat in {"MessageDigest.getInstance"}
	contains(line, _pat)
	not contains(line, "verify")
	finding := {
		"rule_id": metadata.id,
		"message": "Hash computed but not compared for integrity verification",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
