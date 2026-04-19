# SPDX-License-Identifier: Apache-2.0
# VNX-1037 - Process Injection

package vulnetix.rules.vnx_1037

import rego.v1

metadata := {
	"id": "VNX-1037",
	"name": "Process Injection",
	"description": "Detects process injection in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1037/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1037],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection"],
}

_has_process_call(line) if contains(line, "python subprocess")
_has_process_call(line) if contains(line, "node child_process")
_has_process_call(line) if contains(line, "go exec.Command")
_has_process_call(line) if contains(line, "java Runtime")
_has_process_call(line) if contains(line, "ruby system")
_has_process_call(line) if contains(line, "php shell_exec")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_process_call(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Process injection detected; use safe APIs and avoid passing user input to process execution",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
