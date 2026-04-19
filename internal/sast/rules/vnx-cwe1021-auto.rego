# SPDX-License-Identifier: Apache-2.0
# VNX-1021 - Improper Restriction of Rendered UI Layers

package vulnetix.rules.vnx_1021

import rego.v1

metadata := {
	"id": "VNX-1021",
	"name": "Improper Restriction of Rendered UI Layers",
	"description": "Detects improper restriction of rendered ui layers in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1021/",
	"languages": ["java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1021],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss"],
}

_has_ui_render(line) if contains(line, "node createElement")
_has_ui_render(line) if contains(line, "python render_template")
_has_ui_render(line) if contains(line, "java innerHTML")
_has_ui_render(line) if contains(line, "ruby erb")
_has_ui_render(line) if contains(line, "php echo")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_ui_render(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Improper restriction of rendered UI layers detected; validate and sanitize user input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
