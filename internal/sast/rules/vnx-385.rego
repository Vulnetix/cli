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
	not _r309_owns(path, raw)
	not _c008_owns(lines, i, raw)
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

# ── lines VNX-309 reports ───────────────────────────────────────────────
# Both operands name the password (user.password == request.form["password"]):
# that is VNX-309's finding, a login decided by comparing the plaintext
# password. Its fix (store a slow salted hash and verify it with the
# library's constant-time check) is this rule's fix too, so the line is
# reported once, there. This is VNX-309's own test, kept in step with it.
_r309_op := `(?:[A-Za-z_$][\w$]*(?:\??(?:\.|->)[\w$]+|\[\s*['"]?[\w$-]+['"]?\s*\]|\(\s*(?:['"][\w-]+['"])?\s*\))*)`

_r309_res := [
	concat("", [`(`, _r309_op, `)\s*(?:===?|!==?)\s*(`, _r309_op, `)`]),
	concat("", [`(`, _r309_op, `)\.equals(?:IgnoreCase)?\(\s*(`, _r309_op, `)\s*\)`]),
	concat("", [`Objects\.equals\(\s*(`, _r309_op, `)\s*,\s*(`, _r309_op, `)\s*\)`]),
	concat("", [`\b(?:strcmp|strcasecmp|hash_equals)\(\s*(`, _r309_op, `)\s*,\s*(`, _r309_op, `)\s*\)`]),
]

_r309_secret(op) if {
	regex.match(`(?i)(pass(word|wd|phrase)|pwd)`, op)
	not regex.match(`(?i)(confirm|repeat|retype|again|verif|matching|new_?pass|newpass|hash|digest|md5|sha\d|crypt|format|policy|strength|length|\blen\b|(^|[._])count\b|type\b|hint|expir|reset|placeholder|changed|enabled|required|field|label|regex|pattern|rule)`, op)
	not regex.match(`(?i)(pass\w*|pwd\w*)[12]['"]?\s*\)?\]?$`, op)
}

_r309_owns(path, line) if {
	not helpers.is_test_path(path)
	regex.match(`(?i)(pass(word|wd|phrase)|pwd)[^\n]*(==|!=|equals)|(==|!=|equals)[^\n]*(pass(word|wd|phrase)|pwd)`, line)
	prose := [l | some l in regex.find_all_string_submatch_n("\"[^\"]*\"|'[^']*'|`[^`]*`", line, -1); contains(l[0], " ")]
	some re in _r309_res
	some m in regex.find_all_string_submatch_n(re, line, 4)
	not _r309_in_prose(prose, m[1])
	_r309_secret(m[1])
	_r309_secret(m[2])
	m[1] != m[2]
}

_r309_in_prose(prose, op) if {
	some l in prose
	contains(l[0], op)
}

# ── lines VNX-CRYPTO-008 reports ────────────────────────────────────────
# A password checked against a value named as a secret, token, digest,
# signature or MAC, next to the hash call that produced it, is VNX-CRYPTO-008's
# timing finding (a secret compared with ordinary equality): the same timing
# channel, so it is reported there. Only that rule's own clearest shape is
# handed over: an operand whose last name part is one of its secret words and
# a hash call on the line or one of the five above.
_c008_words := {"signature", "sig", "hmac", "mac", "digest", "hexdigest", "token", "secret", "csrf", "xsrf", "otp"}

_c008_pairs(text) := [[m[1], m[2]] |
	some m in regex.find_all_string_submatch_n(`([\w$.]+(?:\([^()]*\))?)\s*(?:===|!==|==|!=|\.equals(?:IgnoreCase)?\s*\(\s*)([\w$.]+(?:\([^()]*\))?)`, text, -1)
]

_c008_secret(op) if {
	not endswith(op, ")")
	segs := regex.find_n(`[\w$\-]+$`, op, 1)
	count(segs) > 0
	parts := [x | some x in regex.split(`[_\-]+`, trim_left(segs[0], "$")); x != ""; not regex.match(`^\d+$`, x)]
	count(parts) > 0
	ws := regex.find_n(`[A-Z]?[a-z0-9]+|[A-Z]+`, parts[count(parts) - 1], -1)
	count(ws) > 0
	lower(ws[count(ws) - 1]) in _c008_words
}

_c008_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# a hash or signing call on the line or one of the five above
_c008_verified(lines, i, _) if {
	some k in numbers.range(max([0, i - 5]), i)
	not helpers.is_comment_line(lines[k])
	regex.match(`(?i)(?:\b|_)(?:hmac|digest|hexdigest|md5|sha\d*|sha\w*hex|hash|sign|signature|crypt)\w*\s*\(|\.doFinal\s*\(|\.Sum(?:256|512)?\s*\(|\bSum(?:224|256|384|512)\s*\(`, _c008_strip(lines[k]))
}

# an operand assigned from a request on one of the 30 lines above
_c008_verified(lines, i, pair) if {
	some op in pair
	segs := regex.find_n(`[\w$]+`, op, 2)
	count(segs) > 0
	x := trim_left(segs[0], "$")
	not x in {"self", "this", "cls"}
	x != ""
	some k in numbers.range(max([0, i - 30]), i - 1)
	t := lines[k]
	contains(t, x)
	regex.match(concat("", [`(?:^|[^\w.$])\$?`, x, `\s*(?:,\s*[\w$]+\s*)*:?=[^=]`]), t)
	regex.match(`(?i)(?:^|[^\w])(?:req|request|params|headers?|cookies?|body|args|query|form)(?:[^\w]|$)|getParameter|getHeader|getCookies|getQueryString`, t)
}

_c008_owns(lines, i, raw) if {
	not regex.match(`compare_digest|timingSafeEqual|hash_equals|hmac\.Equal|ConstantTimeCompare|isEqual|secure_compare|safe_str_cmp|constant_time_compare|constantTimeEquals|timing_safe|timingsafe|typeof`, raw)
	some pair in _c008_pairs(_c008_strip(raw))
	some op in pair
	_c008_secret(op)
	_c008_verified(lines, i, pair)
}
