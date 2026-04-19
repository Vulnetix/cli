# SPDX-License-Identifier: Apache-2.0
# VNX-1045 - File Upload without Type Restriction

package vulnetix.rules.vnx_1045

import rego.v1

metadata := {
	"id": "VNX-1045",
	"name": "File Upload without Type Restriction",
	"description": "Detects file upload without type restriction in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1045/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1045],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal"],
}

_has_upload(line) if contains(line, "python .save")
_has_upload(line) if contains(line, "node upload")
_has_upload(line) if contains(line, "go CreateFile")
_has_upload(line) if contains(line, "java File.createTempFile")
_has_upload(line) if contains(line, "php move_uploaded_file")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_upload(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File upload detected without type restriction",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
