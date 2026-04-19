# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_327

import rego.v1

metadata := {
	"id": "VNX-327",
	"name": "Use of a broken or risky cryptographic algorithm",
	"description": "The code uses MD5, SHA-1, DES, RC4, Blowfish, or another algorithm that is cryptographically broken or too weak for modern security requirements. These algorithms are vulnerable to collision attacks, brute force, or known-plaintext attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-327/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "md5", "sha1", "des", "rc4", "blowfish", "weak-algorithm"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_weak_algo_patterns := {
	# Python
	"hashlib.md5(",
	"hashlib.sha1(",
	"Crypto.Cipher.DES",
	"Crypto.Cipher.Blowfish",
	"Crypto.Cipher.ARC4",
	# Java
	`MessageDigest.getInstance("MD5")`,
	`MessageDigest.getInstance("SHA-1")`,
	`MessageDigest.getInstance("SHA1")`,
	`Cipher.getInstance("DES/`,
	`Cipher.getInstance("DES")`,
	`Cipher.getInstance("RC4")`,
	`Cipher.getInstance("Blowfish")`,
	# JavaScript / Node.js
	"crypto.createHash('md5')",
	`crypto.createHash("md5")`,
	"crypto.createHash('sha1')",
	`crypto.createHash("sha1")`,
	"crypto.createCipheriv('des",
	`crypto.createCipheriv("des`,
	"crypto.createCipheriv('rc4",
	`crypto.createCipheriv("rc4`,
	# PHP
	"mcrypt_encrypt(",
	"mcrypt_decrypt(",
	# Ruby
	"Digest::MD5.",
	"Digest::SHA1.",
	`OpenSSL::Cipher.new("DES`,
	`OpenSSL::Cipher.new('DES`,
	# Go
	`"crypto/md5"`,
	`"crypto/sha1"`,
	`"crypto/des"`,
	`"crypto/rc4"`,
	"md5.New(",
	"sha1.New(",
	"des.NewCipher(",
	"des.NewTripleDESCipher(",
	"rc4.NewCipher(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _weak_algo_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Broken or risky cryptographic algorithm detected (pattern: %s); replace with AES-GCM, SHA-256, or SHA-3", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
