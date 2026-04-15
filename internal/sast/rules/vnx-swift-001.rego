package vulnetix.rules.vnx_swift_001

import rego.v1

metadata := {
	"id": "VNX-SWIFT-001",
	"name": "Swift hardcoded API key or secret in source",
	"description": "A string literal that appears to be an API key, secret token, or private key is hardcoded in Swift source code. Hardcoded secrets can be extracted by anyone with access to the binary or source and cannot be rotated without a code change.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-001/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["hardcoded-secrets", "swift", "ios"],
}

_is_swift(path) if endswith(path, ".swift")

_secret_patterns := {
	`(?i)(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|private[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*"[^"]{8,}"`,
	`(?i)(password|passwd|secret)\s*[:=]\s*"[^"]{4,}"`,
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not regex.match(`^\s*//`, line)
	some pattern in _secret_patterns
	regex.match(pattern, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded secret detected in Swift source; store sensitive credentials in the Keychain or retrieve them from a secure server at runtime — never embed them in source code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
