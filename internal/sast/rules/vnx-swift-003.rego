package vulnetix.rules.vnx_swift_003

import rego.v1

metadata := {
	"id": "VNX-SWIFT-003",
	"name": "Swift insecure data storage via UserDefaults for sensitive values",
	"description": "Sensitive data (passwords, tokens, keys) is stored in NSUserDefaults/UserDefaults which stores data as a plaintext plist file. This data is not encrypted and can be accessed by other apps with sufficient privileges or by extracting the device backup.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-003/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [311],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["insecure-storage", "swift", "ios"],
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
	"apikey",
	"api_key",
	"privateKey",
	"private_key",
	"authToken",
	"auth_token",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "UserDefaults")
	contains(line, ".set(")
	some term in _sensitive_terms
	contains(line, term)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive data stored in UserDefaults; use the iOS Keychain (Security framework) to store passwords, tokens, and cryptographic keys securely",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
