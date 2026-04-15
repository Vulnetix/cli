package vulnetix.rules.vnx_py_017

import rego.v1

metadata := {
	"id": "VNX-PY-017",
	"name": "MD5 or SHA1 used as password hash",
	"description": "hashlib.md5() or hashlib.sha1() is used to hash a password. Both algorithms are cryptographically broken, fast to brute-force, and unsuitable for password storage. Use a purpose-built password hashing function such as hashlib.scrypt(), bcrypt, or Argon2.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-017/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-49"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["cryptography", "password", "hash", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hashlib\.md5\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "hashlib.md5() is not a safe password hashing function; use hashlib.scrypt(), bcrypt, or Argon2 for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hashlib\.sha1\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "hashlib.sha1() is not a safe password hashing function; use hashlib.scrypt(), bcrypt, or Argon2 for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hashlib\.new\s*\(\s*["'](md5|sha1|MD5|SHA1)["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "hashlib.new() with md5/sha1 is not a safe password hashing function; use hashlib.scrypt(), bcrypt, or Argon2 for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
