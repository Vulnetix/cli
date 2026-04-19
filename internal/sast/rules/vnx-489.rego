# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_489

import rego.v1

metadata := {
	"id": "VNX-489",
	"name": "Active debug code",
	"description": "Debug settings and development-only code left active in production expose detailed error messages, stack traces, and internal state to attackers, significantly reducing the effort required to exploit other vulnerabilities.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-489/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [489],
	"capec": ["CAPEC-121"],
	"attack_technique": ["T1082"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["debug", "misconfiguration", "information-disclosure"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"DEBUG = True",
	"app.run(debug=True",
	"app.run(debug = True",
	"error_reporting(E_ALL)",
	"display_errors = On",
	"display_errors=On",
	"display_errors = true",
	"spring.profiles.active=dev",
	"spring.profiles.active=development",
	"config.log_level = :debug",
	"config.consider_all_requests_local = true",
	"config.action_controller.perform_caching = false",
	"WP_DEBUG, true",
	"define('WP_DEBUG', true",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Active debug code: '%v' should not be enabled in production — remove or disable before deploying", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
