package vulnetix.rules.vnx_swift_002

import rego.v1

metadata := {
	"id": "VNX-SWIFT-002",
	"name": "Swift NSLog with potentially sensitive data",
	"description": "NSLog outputs data to the system console log which is readable by any application on the device (and on older iOS versions via iTunes). Logging sensitive information such as passwords, tokens, or PII exposes it to other apps or attackers with device access.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-002/",
	"languages": ["swift"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["logging", "sensitive-data", "swift", "ios"],
}

_is_swift(path) if endswith(path, ".swift")

_sensitive_terms := {
	"password",
	"Password",
	"passwd",
	"token",
	"Token",
	"secret",
	"Secret",
	"apiKey",
	"api_key",
	"privateKey",
	"private_key",
	"credential",
	"Credential",
	"ssn",
	"creditCard",
	"credit_card",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bNSLog\s*\(`, line)
	some term in _sensitive_terms
	contains(line, term)
	finding := {
		"rule_id": metadata.id,
		"message": "NSLog call may expose sensitive data to the system log; remove sensitive fields from log output or use os_log with privacy annotations (.private) in production builds",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
