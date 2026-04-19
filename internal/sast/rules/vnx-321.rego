# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_321

import rego.v1

metadata := {
	"id": "VNX-321",
	"name": "Use of hard-coded cryptographic key",
	"description": "A cryptographic key (AES, RSA, HMAC, or similar) is assigned a string or byte literal in source code. Hard-coded keys can be extracted from binaries and version control history, rendering the cryptography ineffective.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-321/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "hardcoded", "key", "aes", "rsa", "hmac"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_key_patterns := {
	`aesKey = "`,
	`aeskey = "`,
	`hmacKey = "`,
	`hmackey = "`,
	`privateKey = "`,
	`private_key = "`,
	`encryptionKey = "`,
	`encryption_key = "`,
	`signingKey = "`,
	`signing_key = "`,
	`secretKey = "`,
	`secret_key = "`,
	`cryptoKey = "`,
	`key = "`,
	`KEY = "`,
	`AES_KEY = "`,
	`HMAC_KEY = "`,
	`PRIVATE_KEY = "`,
	`aesKey := "`,
	`hmacKey := "`,
	`privateKey := "`,
	`signingKey := "`,
	`secretKey := "`,
}

_pem_patterns := {
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	"-----BEGIN DSA PRIVATE KEY-----",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	not endswith(path, ".pem")
	not endswith(path, ".key")
	not endswith(path, ".p12")
	not endswith(path, ".pfx")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _key_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Hard-coded cryptographic key detected (pattern: %s); load keys from environment variables or a key management service", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	not endswith(path, ".pem")
	not endswith(path, ".key")
	not endswith(path, ".p12")
	not endswith(path, ".pfx")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _pem_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": "PEM-encoded private key embedded in source file; store keys outside the repository and load at runtime",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
