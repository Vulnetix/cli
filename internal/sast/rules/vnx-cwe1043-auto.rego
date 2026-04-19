# SPDX-License-Identifier: Apache-2.0
# VNX-1043 - Non-Thread-Safe Lock

package vulnetix.rules.vnx_1043

import rego.v1

metadata := {
	"id": "VNX-1043",
	"name": "Non-Thread-Safe Lock",
	"description": "Detects non-thread-safe lock in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1043/",
	"languages": ["go", "java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1043],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto"],
}

_has_lock(line) if contains(line, "java synchronized")
_has_lock(line) if contains(line, "python threading")
_has_lock(line) if contains(line, "go Mutex")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_lock(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Non-thread-safe lock detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
