package vulnetix.rules.vnx_cs_006

import rego.v1

metadata := {
	"id": "VNX-CS-006",
	"name": "C# insecure random number generator (System.Random for security)",
	"description": "System.Random is a pseudo-random number generator seeded from a predictable value. It must not be used for cryptographic purposes such as generating tokens, keys, nonces, or passwords. Use System.Security.Cryptography.RandomNumberGenerator instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-006/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-random", "cryptography", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_security_context_keywords := {
	"password",
	"Password",
	"token",
	"Token",
	"secret",
	"Secret",
	"key",
	"Key",
	"nonce",
	"Nonce",
	"salt",
	"Salt",
	"session",
	"Session",
	"csrf",
	"CSRF",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`new\s+Random\s*\(|Random\s+\w+\s*=\s*new\s+Random`, line)
	# Check surrounding 20 lines for security-related keywords
	window_start := max([0, i - 5])
	window_end := min([count(lines) - 1, i + 15])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	some kw in _security_context_keywords
	contains(window, kw)
	finding := {
		"rule_id": metadata.id,
		"message": "System.Random used in a security-sensitive context; replace with System.Security.Cryptography.RandomNumberGenerator.GetBytes() for cryptographically secure random values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Also flag NextBytes() calls specifically used for key material
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bNextBytes\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "System.Random.NextBytes() used for byte generation; use RandomNumberGenerator.GetBytes() for cryptographically secure random bytes",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
