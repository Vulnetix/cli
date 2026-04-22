# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_698

import rego.v1

metadata := {
	"id": "VNX-698",
	"name": "Execution After Redirect (EAR)",
	"description": "Detects source patterns associated with CWE-698 (Execution After Redirect (EAR)). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-698/",
	"languages": ["php", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [698],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["execution-after-redirect", "cwe-698"],
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
	contains(line, "\n")
	some _pat in {"return redirect("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect returned but execution continues — EAR",
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"header(\"Location:"}
	contains(line, _pat)
	not contains(line, "exit;")
	finding := {
		"rule_id": metadata.id,
		"message": "PHP header(Location) without exit — execution continues after redirect",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
