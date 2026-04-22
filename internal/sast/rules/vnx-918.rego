# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_918

import rego.v1

metadata := {
	"id": "VNX-918",
	"name": "Server-Side Request Forgery (SSRF)",
	"description": "Detects source patterns associated with CWE-918 (Server-Side Request Forgery (SSRF)). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-918/",
	"languages": ["node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssrf", "cwe-918"],
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "request.args")
	some _pat in {"requests.get("}
	contains(line, _pat)
	not contains(line, "allowlist")
	finding := {
		"rule_id": metadata.id,
		"message": "SSRF — requests.get with unvalidated user URL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "req.")
	some _pat in {"axios.get(", "fetch("}
	contains(line, _pat)
	not contains(line, "allowlist")
	finding := {
		"rule_id": metadata.id,
		"message": "SSRF — fetch/axios with user URL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
