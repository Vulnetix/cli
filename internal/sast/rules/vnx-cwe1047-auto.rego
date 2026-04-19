# SPDX-License-Identifier: Apache-2.0
# VNX-1047 - SSRF without Timeout

package vulnetix.rules.vnx_1047

import rego.v1

metadata := {
	"id": "VNX-1047",
	"name": "SSRF without Timeout",
	"description": "Detects ssrf without timeout in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1047/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1047],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssrf"],
}

_has_ssrf_pattern(line) if contains(line, "python urllib")
_has_ssrf_pattern(line) if contains(line, "node http.request")
_has_ssrf_pattern(line) if contains(line, "go http.Get")
_has_ssrf_pattern(line) if contains(line, "java URLConnection")
_has_ssrf_pattern(line) if contains(line, "php file_get_contents")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_ssrf_pattern(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SSRF detected; ensure timeouts are set for external requests",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
