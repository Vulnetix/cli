package vulnetix.rules.vnx_go_008

import rego.v1

metadata := {
	"id": "VNX-GO-008",
	"name": "Go weak PRNG for security",
	"description": "Using math/rand instead of crypto/rand for security-sensitive values (tokens, passwords, session IDs) produces predictable output that attackers can guess.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-008/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [338],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["prng", "randomness", "crypto"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`"math/rand"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "math/rand is not cryptographically secure; use crypto/rand for security-sensitive random values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
