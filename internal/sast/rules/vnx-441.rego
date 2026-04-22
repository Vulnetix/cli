# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_441

import rego.v1

metadata := {
	"id": "VNX-441",
	"name": "CWE-441",
	"description": "Detects source patterns associated with CWE-441 (CWE-441). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-441/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [441],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["confused-deputy", "cwe-441"],
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
	contains(line, "user_url")
	contains(line, "target_url")
	some _pat in {"request.get(", "requests.get("}
	contains(line, _pat)
	not contains(line, "allowlist")
	finding := {
		"rule_id": metadata.id,
		"message": "Service fetches URL from user input — confused deputy / SSRF without allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
