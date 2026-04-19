# SPDX-License-Identifier: Apache-2.0
# VNX-1046 - Open Redirect to Untrusted Site

package vulnetix.rules.vnx_1046

import rego.v1

metadata := {
	"id": "VNX-1046",
	"name": "Open Redirect to Untrusted Site",
	"description": "Detects open redirect to untrusted site in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1046/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1046],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["redirect"],
}

_has_redirect(line) if contains(line, "python redirect")
_has_redirect(line) if contains(line, "node res.redirect")
_has_redirect(line) if contains(line, "go http.Redirect")
_has_redirect(line) if contains(line, "java sendRedirect")
_has_redirect(line) if contains(line, "php header")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_redirect(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Open redirect detected; validate redirect URLs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
