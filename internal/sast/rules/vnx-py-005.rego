package vulnetix.rules.vnx_py_005

import rego.v1

metadata := {
	"id": "VNX-PY-005",
	"name": "Weak PRNG for security operations",
	"description": "The random module uses a Mersenne Twister PRNG that is predictable. For security-sensitive values (tokens, passwords, nonces, salts), use the secrets module instead.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-005",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cryptography", "prng", "randomness"],
}

_is_py(path) if endswith(path, ".py")

# Only flag random usage in files with security-related context.
_security_context(content) if contains(content, "password")
_security_context(content) if contains(content, "token")
_security_context(content) if contains(content, "secret")
_security_context(content) if contains(content, "nonce")
_security_context(content) if contains(content, "salt")
_security_context(content) if contains(content, "otp")
_security_context(content) if contains(content, "session")

_random_calls := ["random.randint(", "random.choice(", "random.random(", "random.uniform(", "random.randrange("]

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	content := input.file_contents[path]
	_security_context(content)
	lines := split(content, "\n")
	some i, line in lines
	some call in _random_calls
	contains(line, call)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is not cryptographically secure; use secrets module for security-sensitive values", [call]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
