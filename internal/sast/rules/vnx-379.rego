# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_379

import rego.v1

metadata := {
	"id": "VNX-379",
	"name": "Creation of Temporary File in Directory with Insecure Permissions",
	"description": "Detects source patterns associated with CWE-379 (Creation of Temporary File in Directory with Insecure Permissions). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-379/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [379],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tempfile-insecure-dir", "cwe-379"],
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
	contains(line, "write")
	some _pat in {"/tmp/", "/var/tmp/"}
	contains(line, _pat)
	not contains(line, "tempfile")
	finding := {
		"rule_id": metadata.id,
		"message": "Writing to /tmp with a static filename — use tempfile.NamedTemporaryFile",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
