# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_347

import rego.v1

metadata := {
	"id": "VNX-347",
	"name": "Improper verification of cryptographic signature",
	"description": "JWT tokens are decoded without verifying the signature, or signature verification is explicitly disabled. An attacker can forge arbitrary tokens and impersonate any user.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-347/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-196"],
	"attack_technique": ["T1550"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["jwt", "signature", "verification", "auth", "token"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_sig_bypass_patterns := {
	# Python PyJWT
	`options={"verify_signature": False}`,
	`options={'verify_signature': False}`,
	`options={"verify_exp": False}`,
	`options={'verify_exp': False}`,
	`algorithms=["none"]`,
	`algorithms=['none']`,
	# JavaScript / Node.js
	"jwt.decode(",
	# note: jwt.verify() is correct; jwt.decode() skips verification in most libs
	`algorithm: 'none'`,
	`algorithm: "none"`,
	`algorithms: ['none']`,
	`algorithms: ["none"]`,
	# Java
	"Jwts.parser()",
	# Ruby
	"JWT.decode(token, nil",
	# PHP
	"JWT::decode($token, null",
	# Go
	"jwt.ParseWithClaims",
	# General — algorithm none
	`"alg":"none"`,
	`"alg": "none"`,
	`'alg':'none'`,
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _sig_bypass_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("JWT signature verification missing or disabled (pattern: %s); always verify JWT signatures with a strong algorithm (RS256, ES256, HS256) and reject 'none'", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
