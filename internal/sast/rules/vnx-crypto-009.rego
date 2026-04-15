package vulnetix.rules.vnx_crypto_009

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-009",
	"name": "Use of cryptographically weak PRNG (rand/srand/random in C/C++)",
	"description": "rand(), srand(), drand48(), lrand48(), and related functions from <stdlib.h> produce predictable, non-cryptographically-secure output. Using these for security-sensitive values such as tokens, nonces, session IDs, or key material allows attackers to predict the output.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-009/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338, 330],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "prng", "c", "rand", "weak-randomness"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(rand|srand|drand48|erand48|lrand48|nrand48|mrand48|jrand48|lcong48|srand48|seed48)\s*\(`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "rand()/srand()/drand48() is not cryptographically secure; use getrandom(), /dev/urandom, or a CSPRNG such as libsodium randombytes_buf() for security-sensitive random values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
