package vulnetix.rules.vnx_kotlin_005

import rego.v1

metadata := {
	"id": "VNX-KOTLIN-005",
	"name": "Kotlin MD5 or SHA-1 used as cryptographic hash",
	"description": "MessageDigest.getInstance() is called with 'MD5' or 'SHA-1'. Both algorithms are broken for cryptographic purposes: MD5 has practical collision attacks and SHA-1 is no longer considered collision resistant. Use SHA-256 or SHA-3 for integrity verification and password hashing should use bcrypt/scrypt/Argon2.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-005/",
	"languages": ["kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-461"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["crypto", "hash", "weak-hash", "kotlin"],
}

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "MessageDigest.getInstance(")
	regex.match(`MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "MD5 or SHA-1 used for cryptographic hashing; both are cryptographically broken — use SHA-256 or SHA-3 for integrity checks, and bcrypt/Argon2 for password hashing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_kotlin(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`DigestUtils\.(md5|md5Hex|getMd5Digest|sha1|sha1Hex)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Apache Commons DigestUtils MD5 or SHA-1 helper used; replace with DigestUtils.sha256Hex() or a stronger algorithm",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
