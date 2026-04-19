# SPDX-License-Identifier: Apache-2.0
# VNX-1048 - Sensitive Data in Referrer

package vulnetix.rules.vnx_1048

import rego.v1

metadata := {
	"id": "VNX-1048",
	"name": "Sensitive Data in Referrer",
	"description": "Detects sensitive data in referrer in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1048/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1048],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["information-disclosure"],
}

_has_request(line) if contains(line, "python requests.get")
_has_request(line) if contains(line, "node fetch")
_has_request(line) if contains(line, "go http.NewRequest")
_has_request(line) if contains(line, "java HttpURLConnection")
_has_request(line) if contains(line, "php curl")

findings contains finding if {
	some path in object.keys(input.file_contents)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_has_request(line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive data in referrer detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
