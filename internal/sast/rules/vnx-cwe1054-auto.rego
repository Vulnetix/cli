# SPDX-License-Identifier: Apache-2.0
# VNX-1054 - GUI Input without Validation

package vulnetix.rules.vnx_1054

import rego.v1

metadata := {
	"id": "VNX-1054",
	"name": "GUI Input without Validation",
	"description": "Detects gui input without validation in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1054/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1054],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss"],
}

_has_gui_input(line) if contains(line, "python input")
_has_gui_input(line) if contains(line, "node prompt")
_has_gui_input(line) if contains(line, "go fmt.Scanf")
_has_gui_input(line) if contains(line, "java JOptionPane")
_has_gui_input(line) if contains(line, "php $_GET")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_gui_input(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "GUI input detected without validation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
