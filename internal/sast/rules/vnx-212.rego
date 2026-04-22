# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_212

import rego.v1

metadata := {
	"id": "VNX-212",
	"name": "Improper Removal of Sensitive Information Before Storage or Transfer",
	"description": "Detects source patterns associated with CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-212/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [212],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["data-handling", "cleanup", "cwe-212"],
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
	some _ext in {".py", ".js", ".ts", ".java", ".go", ".php"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "password")
	contains(line, "secret")
	some _pat in {"session.save", "writeFile("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Persisting object containing sensitive field without removing it first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
