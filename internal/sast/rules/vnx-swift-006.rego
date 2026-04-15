package vulnetix.rules.vnx_swift_006

import rego.v1

metadata := {
	"id": "VNX-SWIFT-006",
	"name": "Swift insecure random number generator (arc4random / rand for security use)",
	"description": "arc4random(), rand(), or Swift standard library random functions are used in a security-sensitive context. These generators are not recommended for cryptographic use. Use SecRandomCopyBytes or CryptoKit for cryptographically secure random values.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-006/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-random", "cryptography", "swift", "ios"],
}

_is_swift(path) if endswith(path, ".swift")

_weak_rng_calls := {
	"arc4random()",
	"arc4random_uniform(",
	"arc4random_buf(",
	"rand()",
	"random()",
	"SystemRandomNumberGenerator(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not regex.match(`^\s*//`, line)
	some call in _weak_rng_calls
	contains(line, call)
	# Flag when in a security-sensitive context (token, key, password, nonce generation)
	window_start := max([0, i - 5])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`(?i)(token|key|password|nonce|salt|secret|otp|csrf|iv\b)`, window)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure random function %s used in security-sensitive context; use SecRandomCopyBytes or CryptoKit.SymmetricKey for cryptographically secure random values", [call]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
