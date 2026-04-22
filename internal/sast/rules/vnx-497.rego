# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_497

import rego.v1

metadata := {
	"id": "VNX-497",
	"name": "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
	"description": "Detects source patterns associated with CWE-497 (Exposure of Sensitive System Information to an Unauthorized Control Sphere). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-497/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [497],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["information-exposure-system", "cwe-497"],
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "user.home")
	contains(line, "user.dir")
	contains(line, "java.version")
	some _pat in {"System.getProperty("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "System property value exposed — may leak environment info",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
