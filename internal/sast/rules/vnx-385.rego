# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_385

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-385",
	"name": "Covert Timing Channel",
	"description": "A password, or a password hash, is checked with an ordinary equality comparison, which returns as soon as the first byte differs, so the time a login takes tells an attacker how much of a guess is right (an observable timing channel; storing or comparing the plaintext password is a further weakness). Reported in Python, JavaScript/TypeScript and Java: ==, !=, === or !== where one operand is named as a password (password, passwd, passphrase, pwd, including user.password, row['password'], getPassword(), passwordHash, hashed_password, adminPassword) and the other operand is a real value; Java a.equals(b)/equalsIgnoreCase, Objects.equals and Arrays.equals with such an operand. Comparisons that continue onto the next line are joined, including a line break before the operator or .equals(. Not reported: presence checks against an empty string, None, null, undefined, a boolean or a number; a string literal or ALL_CAPS constant operand (hard-coded credentials are reported by other rules); confirmation, policy, length, field, type and similar names (password_confirmation, passwordPolicy, password.length); a new-versus-old password reuse check; `pwd` naming the working directory (assigned from a cwd call, user.dir or PWD in the same file); lines that already use a constant-time or hashing comparison (hmac.compare_digest, secrets.compare_digest, crypto.timingSafeEqual, MessageDigest.isEqual, bcrypt/check_password/PasswordEncoder.matches); the text in strings and comments; and test code. MAC, signature and token comparisons are reported by VNX-CRYPTO-008.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-385/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [385],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["covert-timing", "cwe-385"],
}

_lang_file(path) if regex.match(`\.(?:py|java|js|jsx|mjs|cjs|ts|tsx)$`, path)

# An expression operand: identifier chains with calls and subscripts.
_op := `[A-Za-z_$][\w$]*(?:\s*(?:\.\s*[A-Za-z_$][\w$]*|\([^()]*\)|\[[^\[\]]*\]))*`

_rhs := concat("", [`(""|\d[\w.]*|`, _op, `)`])

_eq_re := concat("", [`(`, _op, `)\s*(?:===|!==|==|!=)\s*`, _rhs])

_equals_re := concat("", [`(`, _op, `)\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*`, _rhs, `\s*\)`])

_util_equals_re := concat("", [`\b(?:Arrays|Objects)\s*\.\s*equals\s*\(\s*(`, _op, `)\s*,\s*`, _rhs, `\s*\)`])

_safe_re := `compare_digest|timingSafeEqual|isEqual\s*\(|secure_compare|hash_equals|constantTime|ConstantTime|bcrypt|checkpw|check_password|\.matches\s*\(|verify\s*\(`

_deny_re := `(?i)confirm|verif|match|repeat|retype|again|polic|length|size|min_?len|max_?len|expir|field|label|type(?:$|[^d])|changed|enabled|required|strength|valid|error|pattern|regex|prompt|text|placeholder|mode|count|visible|hint|encoder|reset|rule|salt|iteration`

# The operand's own name: call arguments and subscripts removed, last segment.
_name(op) := n if {
	s := regex.replace(regex.replace(op, `\([^()]*\)`, "()"), `\[[^\[\]]*\]`, "")
	parts := split(regex.replace(s, `\s+`, ""), ".")
	n := parts[count(parts) - 1]
}

_pw(op) if regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, _name(op))

_literal(op) if regex.match(`^(?:""|\d[\w.]*|None|null|undefined|nil|True|False|true|false|NaN)$`, op)

# ALL_CAPS constant, possibly qualified (Config.DEFAULT_PASSWORD).
_literal(op) if regex.match(`^[A-Z][A-Z0-9_]*$`, _name(op))

_denied(op) if regex.match(_deny_re, _name(op))

_reuse_check(a, b) if {
	_pw(a)
	_pw(b)
	regex.match(`(?i)new|old|prev|current|cur_`, concat(" ", [_name(a), _name(b)]))
}

_bad_pair(a, b) if {
	_pw(a)
	_ok_other(a, b)
}

_bad_pair(a, b) if {
	_pw(b)
	_ok_other(a, b)
}

_ok_other(a, b) if {
	not _literal(a)
	not _literal(b)
	not _denied(a)
	not _denied(b)
	not _reuse_check(a, b)
	not _equality_impl(a)
	not _equality_impl(b)
	not regex.match(`^(?:len|typeof|type|str|int)\(`, a)
	not regex.match(`^(?:len|typeof|type|str|int)\(`, b)
}

# Subscripts with a literal key become attributes, then string literals are
# blanked so a quoted snippet or a field name is not an operand.
_normalise(line) := s if {
	a := regex.replace(line, `\[\s*["'](\w+)["']\s*\]`, ".$1")
	b := regex.replace(a, `"(?:[^"\\\n]|\\.)*"`, `""`)
	c := regex.replace(b, `'(?:[^'\\\n]|\\.)*'`, `""`)
	d := regex.replace(c, "`(?:[^`\\\\]|\\\\.)*`", `""`)
	s := regex.replace(d, `\s(?:#|//).*$`, "")
}

# A comparison that continues on the next line is joined to it.
_joined(lines, i) := t if {
	regex.match(`(?:==|!=|===|!==|\\|\(|,)\s*$`, lines[i])
	i + 1 < count(lines)
	t := concat(" ", [trim_suffix(trim_right(lines[i], " \t"), "\\"), trim_space(lines[i + 1])])
} else := t if {
	# The operator starts the next line: `a.getPasswordHash()\n    .equals(b)`.
	i + 1 < count(lines)
	regex.match(`^\s*(?:\.\s*equals(?:IgnoreCase)?\s*\(|===|!==|==|!=)`, lines[i + 1])
	t := concat(" ", [trim_right(lines[i], " \t"), trim_space(lines[i + 1])])
} else := lines[i]

# `pwd` that names the working directory, not a password.
_cwd_pwd(content, text) if {
	not regex.match(`(?i)pass(?:word|wd|phrase)`, text)
	regex.match(`(?mi)pwd\w*\s*:?=\s*[^\n]*(?:cwd\s*\(|user\.dir|["']PWD["']|\$PWD)`, content)
}

_comparisons(text) := [[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_eq_re, text, -1)]

_comparisons_eq(text) := [[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_equals_re, text, -1)]

_comparisons_util(text) := [[m[1], m[2]] | some m in regex.find_all_string_submatch_n(_util_equals_re, text, -1)]

_hit(text) if {
	some p in _comparisons(text)
	_bad_pair(_strip_neg(p[0]), p[1])
}

_hit(text) if {
	contains(text, "equals")
	some p in array.concat(_comparisons_eq(text), _comparisons_util(text))
	_bad_pair(_strip_neg(p[0]), p[1])
}

# `not x == y` / `and`/`or` keywords are not part of the operand.
_strip_neg(op) := regex.replace(op, `^(?:not|and|or|return|if|elif|while)\s+`, "")

findings contains finding if {
	some path, content in input.file_contents
	_lang_file(path)
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, raw)
	_has_operator(lines, i, raw)
	not helpers.is_comment_line(raw)
	text := _normalise(_joined(lines, i))
	not regex.match(_safe_re, text)
	_hit(text)
	not _cwd_pwd(content, text)
	finding := {
		"rule_id": metadata.id,
		"message": "Password compared with an ordinary equality test, which leaks through response timing how much of a guess matches: store a salted hash and verify it with the hashing library's own check (bcrypt.checkpw, PasswordEncoder.matches) or a constant-time comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# An equality implementation compares two objects' fields: `self.password ==
# other.password`, `Objects.equals(password, that.password)`.
_equality_impl(op) if regex.match(`^(?:other|that|rhs|o)\s*\.|^getattr\s*\(`, op)

_has_operator(_, _, raw) if regex.match(`==|!=|equals`, raw)

_has_operator(lines, i, raw) if {
	not regex.match(`==|!=|equals`, raw)
	i + 1 < count(lines)
	regex.match(`^\s*(?:\.\s*equals|==|!=)`, lines[i + 1])
}
