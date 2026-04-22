# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1236

import rego.v1

metadata := {
	"id": "VNX-1236",
	"name": "Improper Neutralization of Formula Elements in a CSV File",
	"description": "Detects source patterns associated with CWE-1236 (Improper Neutralization of Formula Elements in a CSV File). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1236/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1236],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["csv-injection", "cwe-1236"],
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
	contains(line, "=")
	contains(line, "+")
	some _pat in {"writeCSV", "to_csv", "csv.writer", "csv.write"}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Writing values that may start with '=','+','-','@' — CSV formula injection risk",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
