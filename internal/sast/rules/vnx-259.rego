# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_259

import rego.v1

metadata := {
	"id": "VNX-259",
	"name": "Use of hard-coded password",
	"description": "A password, secret, or API key is assigned a string literal in source code. Hard-coded credentials are trivially extracted from binaries or version control history and cannot be rotated without a code change.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-259/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [259],
	"capec": ["CAPEC-191", "CAPEC-49"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["credentials", "hardcoded", "password", "secret", "api-key"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_patterns := {
	`password = "`,
	`passwd = "`,
	`secret = "`,
	`api_key = "`,
	`apiKey = "`,
	`private_key = "`,
	`privateKey = "`,
	`PASSWORD = "`,
	`SECRET = "`,
	`API_KEY = "`,
	`password := "`,
	`Password: "`,
	`password='`,
	`passwd='`,
	`secret='`,
	`$password = "`,
	`$passwd = "`,
	`$secret = "`,
	`.setPassword("`,
	`String password = "`,
	`password: "`,
	`apiKey: "`,
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Hard-coded credential detected (pattern: %s); use environment variables or a secrets manager instead", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
