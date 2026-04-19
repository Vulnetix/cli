# SPDX-License-Identifier: Apache-2.0
# VNX-1025 - Improper Comparison of User-Supplied Input

package vulnetix.rules.vnx_1025

import rego.v1

metadata := {
	"id": "VNX-1025",
	"name": "Improper Comparison of User-Supplied Input",
	"description": "Detects improper comparison of user-supplied input in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1025/",
	"languages": ["go", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1025],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto"],
}

_has_comparison(line) if contains(line, "python ==")
_has_comparison(line) if contains(line, "node ===")
_has_comparison(line) if contains(line, "go ==")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_comparison(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Improper comparison of user-supplied input detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
