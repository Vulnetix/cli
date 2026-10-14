# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_327

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-327",
	"name": "Broken or risky hash algorithm (MD5, SHA-1)",
	"description": "MD5 or SHA-1 is computed through a hash API. Both are broken for collision resistance and must not protect integrity, authenticity or passwords; use SHA-256 or stronger (and a password hash such as argon2 or bcrypt for credentials). The rule matches calls into the algorithm, not the words: a field named SHA1, a JSON tag, an enum of algorithm names or a comment is not a use. HMAC-SHA1 is not reported. Go is covered by the dedicated VNX-CRYPTO-001 and VNX-CRYPTO-002 rules, which recognise the same calls.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-327/",
	"languages": ["java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "weak-algorithm", "cwe-327"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

_skip(path) if endswith(path, ".min.html")

# extension → the call shapes that compute the digest
_call_patterns := {
	".py": [
		`\bhashlib\.(md5|sha1)\s*\(`,
		`\bhashlib\.new\(\s*['"](md5|sha1)['"]`,
	],
	".js": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".jsx": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".mjs": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".cjs": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".ts": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".tsx": [`\bcreateHash\(\s*['"](md5|sha-?1)['"]`],
	".java": [`\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"`],
	".kt": [`\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"`],
	".php": [`(^|[^\w>:$])(md5|sha1)(_file)?\s*\(`],
	".rb": [`\b(OpenSSL::)?Digest::(MD5|SHA1)\b`],
}

# HMAC over SHA-1 is not the collision-resistance use this rule is about.
_hmac(line) if regex.match(`(?i)hmac`, line)

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	not helpers.is_test_path(path)
	some ext, patterns in _call_patterns
	endswith(path, ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not _hmac(line)
	some pat in patterns
	regex.match(pat, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Broken hash algorithm (MD5/SHA-1) computed here; migrate to SHA-256 or stronger (argon2/bcrypt for passwords)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
