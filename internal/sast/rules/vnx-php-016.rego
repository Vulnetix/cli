package vulnetix.rules.vnx_php_016

import rego.v1

metadata := {
	"id": "VNX-PHP-016",
	"name": "PHP weak hash function (md5/sha1)",
	"description": "md5() or sha1() is used in a context that appears to be password or secret hashing. MD5 and SHA1 are cryptographically broken and unsuitable for password storage. Use password_hash($password, PASSWORD_BCRYPT) or password_hash($password, PASSWORD_ARGON2ID) for passwords, and hash('sha256', ...) for general-purpose non-password hashing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-016/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-55"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-crypto", "hashing", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bmd5\s*\(`, line)
	regex.match(`(?i)(password|passwd|secret|credential|hash)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Weak hash: md5() is cryptographically broken and unsuitable for passwords — use password_hash($password, PASSWORD_BCRYPT) instead",
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bsha1\s*\(`, line)
	regex.match(`(?i)(password|passwd|secret|credential|hash)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Weak hash: sha1() is cryptographically broken and unsuitable for passwords — use password_hash($password, PASSWORD_BCRYPT) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
