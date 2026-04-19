# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_916

import rego.v1

metadata := {
	"id": "VNX-916",
	"name": "Password hash with insufficient computational effort",
	"description": "Using fast, general-purpose hash functions (MD5, SHA-1, SHA-256) to store passwords is insecure because they can be brute-forced with GPUs at billions of guesses per second. Use a slow, memory-hard algorithm (bcrypt, Argon2, PBKDF2, scrypt) designed specifically for passwords.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-916/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [916],
	"capec": ["CAPEC-55"],
	"attack_technique": ["T1110.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-hash", "passwords", "crypto"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"hashlib.md5(password",
	"hashlib.sha1(password",
	"hashlib.sha256(password",
	"hashlib.md5(pass",
	"hashlib.sha1(pass",
	"md5($password",
	"sha1($password",
	"md5($pass",
	"sha1($pass",
	"MessageDigest.getInstance(\"MD5\")",
	"MessageDigest.getInstance(\"SHA-1\")",
	"MessageDigest.getInstance(\"SHA1\")",
	"Digest::MD5.hexdigest(password",
	"Digest::SHA1.hexdigest(password",
	"Digest::SHA256.hexdigest(password",
	"createHash('md5').update(password",
	"createHash('sha1').update(password",
	"createHash('sha256').update(password",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak password hash: '%v' uses a fast hash algorithm for passwords — use bcrypt, Argon2, or PBKDF2 instead", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
