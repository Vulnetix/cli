# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_328

import rego.v1

metadata := {
	"id": "VNX-328",
	"name": "Use of weak hash",
	"description": "The code uses MD5, SHA-1, CRC32, or another weak hash function. These produce short or collision-prone digests that are unsuitable for password hashing or integrity verification of security-sensitive data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-328/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-97", "CAPEC-461"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["crypto", "hash", "md5", "sha1", "crc32", "weak-hash"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_weak_hash_patterns := {
	# Python
	"hashlib.md5(",
	"hashlib.sha1(",
	"hashlib.new('md5'",
	`hashlib.new("md5"`,
	"hashlib.new('sha1'",
	`hashlib.new("sha1"`,
	# Java
	`MessageDigest.getInstance("MD5")`,
	`MessageDigest.getInstance("SHA-1")`,
	`MessageDigest.getInstance("SHA1")`,
	`DigestUtils.md5(`,
	`DigestUtils.sha1(`,
	# JavaScript / Node.js
	"crypto.createHash('md5')",
	`crypto.createHash("md5")`,
	"crypto.createHash('sha1')",
	`crypto.createHash("sha1")`,
	"crypto.createHash('sha-1')",
	`crypto.createHash("sha-1")`,
	# PHP
	"md5(",
	"sha1(",
	"crc32(",
	"hash('md5'",
	`hash("md5"`,
	"hash('sha1'",
	`hash("sha1"`,
	# Ruby
	"Digest::MD5.",
	"Digest::SHA1.",
	"Digest::CRC32.",
	# Go
	"md5.New(",
	"sha1.New(",
	`"crypto/md5"`,
	`"crypto/sha1"`,
	`"hash/crc32"`,
	`"hash/adler32"`,
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _weak_hash_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak hash function detected (pattern: %s); use SHA-256 or SHA-3 for integrity checks, bcrypt/argon2 for password hashing", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
