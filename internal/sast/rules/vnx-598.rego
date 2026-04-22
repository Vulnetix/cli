# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_598

import rego.v1

metadata := {
	"id": "VNX-598",
	"name": "CWE-598",
	"description": "Detects source patterns associated with CWE-598 (CWE-598). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-598/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [598],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["sensitive-data-in-url", "cwe-598"],
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
	some _pat in {"?password=", "?api_key=", "?token=", "&password=", "&api_key=", "&token="}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive value in URL query string — goes to logs/referer; use POST body / auth header",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
