# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_205

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-205",
	"name": "Observable Behavioral Discrepancy",
	"description": "A login path skips the password hash when the account does not exist, so an unknown username answers measurably faster than a known one with a wrong password and the timing reveals which accounts exist. Reported in Python and JavaScript/TypeScript: a check that the looked-up account is missing (if user is None:, if not user:, if (!user), if (user == null)) whose branch returns, raises, aborts or throws without running a hash, followed within 12 lines by a password verification of that account (bcrypt.checkpw, check_password, check_password_hash, verify_password, pwd_context.verify, argon2/hasher .verify, bcrypt.compare/compareSync); and the short-circuit form if user is None or not check_password(...) / if (!user || !(await bcrypt.compare(...))) and its positive twin if user and checkpw(..., user.hash) / return user && bcrypt.compare(..., user.hash), where the hash is skipped for a missing account. Not reported: a branch that verifies against a dummy hash or calls set_password/hashpw first, a verification that runs before the account check (compare(pw, user ? user.hash : DUMMY)), a missing-record check with no password verification after it (a profile lookup), comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-205/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [205],
	"capec": ["CAPEC-575"],
	"attack_technique": ["T1589"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["behavior-discrepancy", "timing", "account-enumeration", "authentication", "cwe-205"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_verify_re := `(?:\bcheckpw|\bcheck_password(?:_hash)?|\bverify_password|\bverifyPassword|\bcheckPassword|\bcomparePassword|\bpwd_context\s*\.\s*verify|\b(?:password_)?hasher\s*\.\s*verify|\bph\s*\.\s*verify|\bargon2\s*\.\s*verify|\bbcrypt\s*\.\s*compare(?:Sync)?|\bbcryptjs\s*\.\s*compare(?:Sync)?|\b\w+_crypt\s*\.\s*verify|\bpbkdf2_sha256\s*\.\s*verify)\s*\(`

# A hash in the missing-account branch equalises the timing.
_hash_re := `(?i)checkpw|hashpw|check_password|set_password|make_password|verify|compare|hash\s*\(|dummy|fake`

_missing_re := {
	"py": `^\s*if\s+(?:not\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s+(?:is|==)\s+None)\s*:(.*)$`,
	"js": `^\s*if\s*\(\s*(?:!\s*([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*===?\s*(?:null|undefined))\s*\)(.*)$`,
}

_short_circuit_re := {
	"py": `^\s*if\s+(?:not\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s+(?:is|==)\s+None)\s+or\s+`,
	"js": `^\s*if\s*\(\s*(?:!\s*([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*===?\s*(?:null|undefined))\s*\|\|`,
}

# The positive form skips the hash the same way: if user and checkpw(...),
# return user && bcrypt.compare(...).
_and_re := {
	"py": `^\s*(?:if|elif|return)\s+\(?\s*([A-Za-z_]\w*)(?:\s+is\s+not\s+None)?\s+and\s+`,
	"js": `^\s*(?:if\s*\(|return\s+|(?:const|let|var)\s+[\w$]+\s*=\s*)\(?\s*([A-Za-z_$][\w$]*)(?:\s*!==?\s*(?:null|undefined))?\s*&&`,
}

_short_circuit(lang, line) := m if {
	m := regex.find_all_string_submatch_n(_short_circuit_re[lang], line, 1)
	count(m) > 0
}

_short_circuit(lang, line) := m if {
	not regex.match(_short_circuit_re[lang], line)
	m := regex.find_all_string_submatch_n(_and_re[lang], line, 1)
	count(m) > 0
}

_exit_re :=`^\s*\{?\s*(?:return\b|raise\b|throw\b|abort\s*\(|flask\.abort\s*\()`

_var(m) := m[0][1] if m[0][1] != ""

_var(m) := m[0][2] if m[0][1] == ""

# The variable was assigned a few lines above (the lookup).
_assigned_above(lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(concat("", [`^\s*(?:const\s+|let\s+|var\s+)?`, v, `\s*(?::[^=]+)?=[^=]`]), lines[j])
}

# Index of the line that leaves the branch: the rest of the if line, or one
# of the next three code lines.
_exit_index(lines, i, rest) := i if regex.match(`^\s*\{?\s*(?:return\b|raise\b|throw\b|abort\s*\(|flask\.abort\s*\()`, rest)

_exit_index(lines, i, rest) := k if {
	not regex.match(_exit_re, rest)
	cands := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
	]
	count(cands) > 0
	some k in cands
	regex.match(_exit_re, lines[k])
	not _earlier_exit(lines, cands, k)
	not _left_branch(lines, cands, i, k)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A code line up to the exit is not indented under the branch: the exit
# belongs to code after it.
_left_branch(lines, cands, i, k) if {
	some c in cands
	c <= k
	_indent(lines[c]) <= _indent(lines[i])
}

_earlier_exit(lines, cands, k) if {
	some c in cands
	c < k
	regex.match(_exit_re, lines[c])
}

_hash_in_branch(lines, i, e) if {
	some k in numbers.range(i, e)
	not helpers.is_comment_line(lines[k])
	regex.match(_hash_re, regex.replace(lines[k], `^\s*if\b[^:{]*`, ""))
}

_verified_after(lines, e, v) if {
	some k in numbers.range(e + 1, min([count(lines) - 1, e + 12]))
	not helpers.is_comment_line(lines[k])
	regex.match(_verify_re, lines[k])
	regex.match(concat("", [`\b`, v, `\b`]), lines[k])
}

_msg := "The login returns early when the account does not exist, before any password hash runs, so an unknown username answers faster than a wrong password and the timing reveals which accounts exist. Verify the password against a dummy hash when the account is missing"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_verify(content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_left(line, " \t"), "if")
	m := regex.find_all_string_submatch_n(_missing_re[lang], line, 1)
	count(m) > 0
	v := _var(m)
	_assigned_above(lines, i, v)
	e := _exit_index(lines, i, m[0][3])
	not _hash_in_branch(lines, i, e)
	_verified_after(lines, e, v)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_verify(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(?:if|elif|return|const|let|var)\b`, line)
	m := _short_circuit(lang, line)
	v := _var(m)
	_assigned_above(lines, i, v)
	regex.match(_verify_re, line)
	regex.match(concat("", [_verify_re, `.*\b`, v, `\b`]), line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python: the lookup raises for a missing account and the handler leaves
# before the hash (except User.DoesNotExist: return None).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "except")
	_has_verify(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*except\s+\(?[\w.]*(?:DoesNotExist|NoResultFound|UserNotFound\w*|AccountNotFound\w*)\b[^:]*:(.*)$`, line)
	m := regex.find_all_string_submatch_n(`:(.*)$`, line, 1)
	e := _exit_index(lines, i, m[0][1])
	not _hash_in_branch(lines, i, e)
	some k in numbers.range(e + 1, min([count(lines) - 1, e + 12]))
	not helpers.is_comment_line(lines[k])
	regex.match(_verify_re, lines[k])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_verify_needles := {"checkpw", "check_password", "verify_password", "verifyPassword", "checkPassword", "comparePassword", ".verify(", "compare(", "compareSync("}

_has_verify(content) if {
	some n in _verify_needles
	contains(content, n)
}
