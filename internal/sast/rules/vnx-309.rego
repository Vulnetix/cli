# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_309

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-309",
	"name": "Use of Password System for Primary Authentication",
	"description": "Authentication is decided by comparing a submitted password directly with a stored or configured one: the password is the sole secret, it is held in a recoverable form, and the comparison is not constant-time. This is the concrete code-level form of CWE-309 that a line-oriented rule can see; whether a deployment adds a second factor elsewhere is not visible. Reported: an equality test (==, ===, !=, !==, .equals(), .equalsIgnoreCase(), Objects.equals(), PHP strcmp/strcasecmp/hash_equals) in Python, JavaScript/TypeScript, Java or PHP whose two operands both name a password (password, passwd, pwd, passphrase), such as user.password == request.form[\"password\"], password === user.password, user.getPassword().equals(password) or $row['password'] == $_POST['password']. Not reported: password-hash verification (check_password_hash, bcrypt.compare, passlib verify, password_verify), operands that hash or measure the password (hash(), md5, digest, length), confirmation checks (password == confirm_password, password1 != password2, new vs old password, matching password), comparisons with null, empty strings or other literals, enum and format comparisons, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-309/",
	"languages": ["java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [309],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["password-as-primary", "cwe-309"],
}

_exts := {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java", ".php"}

_op := `(?:[A-Za-z_$][\w$]*(?:\??(?:\.|->)[\w$]+|\[\s*['"]?[\w$-]+['"]?\s*\]|\(\s*(?:['"][\w-]+['"])?\s*\))*)`

_cmp_re := concat("", [`(`, _op, `)\s*(?:===?|!==?)\s*(`, _op, `)`])

_equals_re := concat("", [`(`, _op, `)\.equals(?:IgnoreCase)?\(\s*(`, _op, `)\s*\)`])

_objeq_re := concat("", [`Objects\.equals\(\s*(`, _op, `)\s*,\s*(`, _op, `)\s*\)`])

# PHP: strcmp($row['password'], $password) === 0, hash_equals on plaintext.
_strcmp_re := concat("", [`\b(?:strcmp|strcasecmp|hash_equals)\(\s*(`, _op, `)\s*,\s*(`, _op, `)\s*\)`])

_pwish := `(?i)(pass(word|wd|phrase)|pwd)`

# Operands that are not the password itself, or a check that is not authentication.
_not_secret := `(?i)(confirm|repeat|retype|again|verif|matching|new_?pass|newpass|hash|digest|md5|sha\d|crypt|format|policy|strength|length|\blen\b|(^|[._])count\b|type\b|hint|expir|reset|placeholder|changed|enabled|required|field|label|regex|pattern|rule)`

_numbered := `(?i)(pass\w*|pwd\w*)[12]['"]?\s*\)?\]?$`

_secret_operand(op) if {
	regex.match(_pwish, op)
	not regex.match(_not_secret, op)
	not regex.match(_numbered, op)
}

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	not helpers.is_test_path(path)
	regex.match(`(?i)(pass(word|wd|phrase)|pwd)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(pass(word|wd|phrase)|pwd)[^\n]*(==|!=|equals)|(==|!=|equals)[^\n]*(pass(word|wd|phrase)|pwd)|(strcmp|strcasecmp|hash_equals)\(`, line)
	not helpers.is_comment_line(line)
	prose := [l | some l in regex.find_all_string_submatch_n("\"[^\"]*\"|'[^']*'|`[^`]*`", line, -1); contains(l[0], " ")]
	some p in _pairs(line)
	not _in_prose(prose, p[0])
	_secret_operand(p[0])
	_secret_operand(p[1])
	p[0] != p[1]
	finding := {
		"rule_id": metadata.id,
		"message": "Login decided by a plain password comparison: store a slow salted hash (bcrypt/argon2/scrypt), verify with the library's constant-time check, and add a second factor",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The comparison is written inside a string literal of prose.
_in_prose(prose, op) if {
	some l in prose
	contains(l[0], op)
}

_pairs(line) :=[[m[1], m[2]] |
	some re in [_cmp_re, _equals_re, _objeq_re, _strcmp_re]
	some m in regex.find_all_string_submatch_n(re, line, 4)
]
