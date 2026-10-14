package vulnetix.rules.vnx_py_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-017",
	"name": "MD5 or SHA1 used as password hash",
	"description": "A password is hashed with MD5 or SHA-1 in a .py file. Reported: hashlib.md5()/hashlib.sha1() (also through `import hashlib as h` and `from hashlib import md5, sha1 as x`), hashlib.new('md5'|'sha1', ...) and PyCryptodome MD5.new()/SHA1.new()/SHA.new() whose argument names a password (password, passwd, passphrase, pwd, pw, a request field keyed 'pass'/'password'), whose argument is a variable assigned from such a value in the 8 lines above, or an .update(password) on a hasher created by one of those calls in the 10 lines above; a call broken across lines is read on its next line. Both algorithms are fast and broken, so a dumped hash is cracked offline in hours; use argon2id, bcrypt, scrypt or PBKDF2 with a high iteration count. Not reported: MD5/SHA-1 of data that is not a password (cache keys, ETags, file checksums), a call with usedforsecurity=False (HTTP digest auth), hashing a password reset token, SHA-256 and the password KDFs, and the calls in comments or string literals. VNX-CRYPTO-007 covers the same weakness across more algorithms and languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-017/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-49"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cryptography", "password", "hash", "python"],
}

# String contents blanked (quotes kept) and trailing comments removed, so a
# call named inside a string or a comment is not a call.
_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

# hashlib and its `import hashlib as x` aliases.
_modules(content) := {"hashlib"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+hashlib\s+as\s+(\w+)`, content, -1)
}

# md5/sha1 from-imported from hashlib, under the name they are bound to.
_from_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
	some part in split(regex.replace(m[1], `[()\\]`, ""), ",")
	words := regex.split(`\s+`, trim_space(part))
	words[0] in {"md5", "sha1"}
	n := words[count(words) - 1]
}

_pycrypto(content) if regex.match(`(?m)^\s*from\s+(?:Crypto|Cryptodome)\.Hash\s+import\b`, content)

# _weak_rest returns the code after the opening parenthesis of a weak-hash
# constructor on this line.
_weak_rest(code, _, ctx) := m[0][1] if {
	some mod in ctx.modules
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, mod, `\.(?:md5|sha1)\s*\((.*)$`]), code, 1)
	count(m) > 0
}

_weak_rest(code, raw, ctx) := m[0][1] if {
	some mod in ctx.modules
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, mod, `\.new\s*\(\s*(?:""|'')(.*)$`]), code, 1)
	count(m) > 0
	regex.match(concat("", [mod, `\.new\s*\(\s*["'](?i:md5|sha-?1)["']`]), raw)
}

_weak_rest(code, _, ctx) := m[0][1] if {
	some n in ctx.from_names
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, n, `\s*\((.*)$`]), code, 1)
	count(m) > 0
}

_weak_rest(code, _, ctx) := m[0][1] if {
	ctx.pycrypto
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:MD5|SHA1?)\.new\s*\((.*)$`, code, 1)
	count(m) > 0
}

# The argument text, extended onto the next code line when the call is
# broken right after its opening parenthesis.
_arg(_, _, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := concat(" ", [lines[j], lines[k]]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
	k := min([j + 1, count(lines) - 1])
}

_pw_re := `(?i)(?:passw(?:or)?d|passphrase|\bpwd|\bpw\b|_pw\b|\bpw_|\bpass\b|\bpass_|_pass\b)`

# A request field keyed by a password name: form["password"], .get('pass').
_pw_key_re := `(?i)(?:\[|\.get\()\s*["'](?:[\w-]*_)?(?:pass(?:word|wd|phrase)?|pwd|pw)(?:_?\d)?["']`

_names_password(arg, _) if regex.match(_pw_re, _code(arg))

_names_password(_, raw) if regex.match(_pw_key_re, raw)

# An f-string interpolating a password: f"{salt}{password}".
_names_password(_, raw) if {
	some m in regex.find_all_string_submatch_n(`\b[fF][rR]?(?:"[^"]*"|'[^']*')`, raw, -1)
	some b in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, m[0], -1)
	regex.match(_pw_re, b[1])
}

_not_password(arg) if regex.match(`(?i)reset|token|usedforsecurity\s*=\s*False`, arg)

# A value assigned from a password expression in the lines above.
_source_re := `(?i)[^=!<>]=[^=].*(?:passw(?:or)?d|passphrase|\bpwd\b|["']pass["'])`

_tainted(lines, i, arg) if {
	some v in helpers.tainted_names(lines, i, 8, _source_re)
	regex.match(concat("", [`\b`, v, `\b`]), _code(arg))
}

_password_arg(_, _, arg, raw) if _names_password(arg, raw)

_password_arg(lines, i, arg, _) if _tainted(lines, i, arg)

_ctx(content) := {
	"modules": _modules(content),
	"from_names": _from_names(content),
	"pycrypto": _has_pycrypto(content),
}

_has_pycrypto(content) := true if _pycrypto(content)

_has_pycrypto(content) := false if not _pycrypto(content)

_findings_in(path, content) := {[i, line] |
	ctx := _ctx(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)md5|sha`, line)
	not helpers.is_comment_line(line)
	rest := _weak_rest(_code(line), line, ctx)
	arg := _arg(lines, i, rest)
	_password_arg(lines, i, arg, line)
	not _not_password(line)
	not _not_password(arg)
}

# h = hashlib.md5(); ... h.update(password)
_update_findings(content) := {[i, line] |
	ctx := _ctx(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".update(")
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\.update\s*\((.*)$`, line, 1)
	count(m) > 0
	h := m[0][1]
	arg := m[0][2]
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	regex.match(concat("", [`^\s*`, h, `\s*=`]), prev)
	_weak_rest(_code(prev), prev, ctx)
	_password_arg(lines, i, arg, line)
	not _not_password(line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?i)md5|sha1|\bSHA\.new`, content)
	some hit in _findings_in(path, content) | _update_findings(content)
	finding := {
		"rule_id": metadata.id,
		"message": "A password is hashed with MD5 or SHA-1, which are fast and broken; use argon2id, bcrypt, scrypt or PBKDF2 with a high iteration count",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": hit[0] + 1,
		"snippet": hit[1],
	}
}
