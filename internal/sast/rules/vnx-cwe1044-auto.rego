# SPDX-License-Identifier: Apache-2.0
# VNX-1044 - File Upload without Size Limit

package vulnetix.rules.vnx_1044

import rego.v1

metadata := {
	"id": "VNX-1044",
	"name": "File Upload without Size Limit",
	"description": "Detects file upload without size limit in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1044/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1044],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal"],
}

_has_upload(line) if contains(line, "python open")
_has_upload(line) if contains(line, "node fs.readFile")
_has_upload(line) if contains(line, "go os.Open")
_has_upload(line) if contains(line, "java FileInputStream")
_has_upload(line) if contains(line, "php move_uploaded_file")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_upload(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File upload detected without size limit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
