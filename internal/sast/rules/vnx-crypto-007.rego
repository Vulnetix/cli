package vulnetix.rules.vnx_crypto_007

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-007",
	"name": "Weak password hashing (insufficient iterations or missing KDF)",
	"description": "Password is hashed using MD5, SHA-1, SHA-256 without a proper KDF, or PBKDF2 with insufficient iterations. These approaches are vulnerable to brute-force and rainbow-table attacks. Use bcrypt, scrypt, or argon2id instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-007/",
	"languages": ["python", "javascript", "typescript", "java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [916],
	"capec": ["CAPEC-16"],
	"attack_technique": ["T1110.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "password-hashing", "weak-crypto"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hashlib\.(md5|sha1|sha256)\s*\(.*password`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with MD5/SHA-1/SHA-256; use a memory-hard KDF such as bcrypt, scrypt, or argon2id for password storage",
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']`, line)
	regex.match(`(password|passwd|pwd)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with MD5 or SHA-1 via MessageDigest; use BCrypt, SCrypt, or Argon2 for password hashing in Java",
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`createHash\s*\(\s*["'](md5|sha1|sha-1)["']`, line)
	regex.match(`(password|passwd|pwd)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with MD5 or SHA-1 via crypto.createHash; use bcrypt, scrypt, or argon2 for password hashing in Node.js",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
