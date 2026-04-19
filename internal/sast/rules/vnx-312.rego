# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_312

import rego.v1

metadata := {
	"id": "VNX-312",
	"name": "Cleartext storage of sensitive information",
	"description": "Passwords, secrets, or other sensitive values are logged or written to storage in plaintext. Cleartext sensitive data in logs or files can be accessed by anyone with log access or file system read permissions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-312/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [312],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["logging", "cleartext", "password", "secret", "storage"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_cleartext_log_patterns := {
	# JavaScript / TypeScript
	"console.log(password",
	"console.log(passwd",
	"console.log(secret",
	"console.log(apiKey",
	"console.log(api_key",
	"console.log(token",
	"console.log(privateKey",
	# Python
	"print(password",
	"print(passwd",
	"print(secret",
	"print(api_key",
	"print(token",
	"logging.info(password",
	"logging.debug(password",
	"logging.warning(password",
	"log.info(password",
	"log.debug(password",
	# Java
	"Logger.info(password",
	"logger.info(password",
	"System.out.println(password",
	"Logger.debug(password",
	"logger.debug(password",
	# Go
	"log.Println(password",
	"log.Printf(password",
	"fmt.Println(password",
	"log.Print(password",
	# Ruby
	"puts password",
	"Rails.logger.info password",
	"logger.info password",
	# PHP
	"error_log($password",
	"echo $password",
	"print $password",
	"var_dump($password",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _cleartext_log_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Sensitive value appears to be logged or stored in cleartext (pattern: %s); mask or omit sensitive fields from logs and storage", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
