# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_330

import rego.v1

metadata := {
	"id": "VNX-330",
	"name": "Use of insufficiently random values",
	"description": "The code uses a non-cryptographic random number generator for a security-sensitive purpose such as generating tokens, passwords, nonces, or session identifiers. Predictable values can be guessed by attackers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-330/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [330],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "random", "prng", "weak-random", "token"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_weak_rand_patterns := {
	# Python — math/random module (not secrets)
	"random.random(",
	"random.randint(",
	"random.choice(",
	"random.uniform(",
	"random.randrange(",
	# Java
	"new Random(",
	"new java.util.Random(",
	"Math.random(",
	# JavaScript / Node.js
	"Math.random(",
	# PHP
	"rand(",
	"mt_rand(",
	"array_rand(",
	"shuffle(",
	# Ruby
	"Kernel.rand(",
	# Go — math/rand import
	`"math/rand"`,
	"rand.Intn(",
	"rand.Float64(",
	"rand.Int(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _weak_rand_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Non-cryptographic random source detected (pattern: %s); use crypto/rand (Go), secrets module (Python), SecureRandom (Java), or crypto.randomBytes (Node.js) for security-sensitive values", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
