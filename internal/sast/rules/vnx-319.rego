# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_319

import rego.v1

metadata := {
	"id": "VNX-319",
	"name": "Cleartext transmission of sensitive information",
	"description": "Sensitive data such as credentials or authentication tokens is transmitted over an unencrypted HTTP connection. An attacker with network access can intercept and read the data in transit.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-319/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["http", "cleartext", "tls", "transmission", "network"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_http_url_patterns := {
	`"http://`,
	`'http://`,
}

# Keywords that increase confidence that the URL carries sensitive data
_sensitive_context_patterns := {
	"login",
	"auth",
	"token",
	"password",
	"credential",
	"secret",
	"api",
	"oauth",
	"jwt",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some url_pattern in _http_url_patterns
	contains(line, url_pattern)
	some ctx_pattern in _sensitive_context_patterns
	contains(lower(line), ctx_pattern)
	not contains(line, "localhost")
	not contains(line, "127.0.0.1")
	not contains(line, "0.0.0.0")
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive data transmitted over plain HTTP; use HTTPS to encrypt data in transit",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
