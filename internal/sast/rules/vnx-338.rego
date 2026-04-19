# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_338

import rego.v1

metadata := {
	"id": "VNX-338",
	"name": "Use of cryptographically weak pseudo-random number generator (PRNG)",
	"description": "The code uses a PRNG that is not cryptographically secure. Weak PRNGs such as java.util.Random, Python's random module, or math/rand in Go produce statistically predictable sequences that attackers can reconstruct after observing a small number of outputs.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-338/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "prng", "random", "weak-random"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_weak_prng_patterns := {
	# Go
	`"math/rand"`,
	"rand.New(rand.NewSource(",
	"rand.Seed(",
	# Java
	"new Random(",
	"new java.util.Random(",
	"ThreadLocalRandom.current(",
	# JavaScript
	"Math.random(",
	# Python
	"import random",
	"from random import",
	"random.seed(",
	"random.getstate(",
	# PHP
	"srand(",
	"mt_srand(",
	"lcg_value(",
	# Ruby
	"Random.new(",
	"srand(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _weak_prng_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cryptographically weak PRNG detected (pattern: %s); replace with a CSPRNG: crypto/rand (Go), secrets (Python), SecureRandom (Java), crypto.randomBytes (Node.js)", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
