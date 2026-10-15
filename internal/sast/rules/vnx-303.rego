# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_303

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-303",
	"name": "Incorrect Implementation of Authentication Algorithm",
	"description": "A password check is implemented so that it cannot give the right answer. Two shapes are reported. In JavaScript/TypeScript, an asynchronous verifier used as if it returned a boolean: bcrypt/bcryptjs .compare() or argon2 .verify() (also as a named or destructured import such as import { compare } from 'bcryptjs') without await, .then() or a callback, inside an if/&&/||/!/ternary (including a condition continued from the line above and a result followed by ? or &&), or assigned to a name that a condition within five lines tests; the Promise is always truthy, so every password is accepted (and !verify(...) never rejects). In Python, Java and JavaScript/TypeScript, a submitted password re-hashed with a fresh random salt and compared with the stored hash (bcrypt.hashpw(pw, bcrypt.gensalt()) ==, werkzeug generate_password_hash(pw) ==, Django make_password(pw) == (one argument, so a fresh salt), passlib/argon2 hasher .hash(pw) ==, Spring passwordEncoder.encode(pw).equals(...), jBCrypt BCrypt.hashpw(pw, BCrypt.gensalt()).equals(...), bcrypt.hash/hashSync(pw, rounds or genSaltSync()) ===), inline or through a name assigned from the hash in the five lines above; a salted hash never repeats, so the check always fails and is typically 'fixed' by weakening it. Not reported: await bcrypt.compare(...), compareSync/checkpw/check_password_hash/matches/verify helpers, a returned Promise, a callback or .then() form, re-hashing with the stored hash as salt (bcrypt.hashpw(pw, stored) == stored), hashing at registration, a null/undefined/empty check on the new hash, two fresh hashes compared with each other (a salting test), make_password with an explicit salt, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-303/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [303],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["auth", "password-verification", "bcrypt", "cwe-303"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Un-awaited async verifier (JavaScript/TypeScript) ────────────────────

_async_verify := `\b(bcrypt|bcryptjs|argon2)\.(compare|verify)\s*\(`

# The call's text up to the line that closes its parentheses.
_call_text(lines, i) := concat("\n", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + _span(lines, i)]))])

_span(lines, i) := s if {
	ends := [d |
		some k in numbers.range(i, min([count(lines) - 1, i + 6]))
		_balance(lines, i, k) <= 0
		d := k - i
	]
	s := min(array.concat([6], ends))
}

_balance(lines, i, k) := sum([n |
	some j in numbers.range(i, k)
	c := _code(lines[j])
	n := (count(split(c, "(")) - 1) - (count(split(c, ")")) - 1)
])

_awaited(prefix) if regex.match(`\b(await|yield)\s*[\(!]*\s*$`, prefix)

_handled(lines, i) if regex.match(`\.then\s*\(|\bfunction\s*\(|=>`, _call_text(lines, i))

_tested(lines, i, prefix, c, vre) if {
	not regex.match(`\breturn\s*$`, prefix)
	_unawaited_use(lines, i, prefix)
}

_tested(lines, i, prefix, c, vre) if _suffix_use(c, vre)

_tested(lines, i, prefix, c, vre) if {
	trim_space(prefix) == ""
	_cond_above(lines, i)
}

# Used directly as a condition.
_unawaited_use(lines, i, prefix) if regex.match(`\bif\s*\(|&&|\|\||!\s*$|\?\s*$|\bwhile\s*\(`, prefix)

# Assigned, then tested.
_unawaited_use(lines, i, prefix) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)?\s*(\w+)\s*=\s*$`, prefix, 1)
	count(m) > 0
	w := m[0][1]
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 5]))
	regex.match(concat("", [`\bif\s*\(\s*!?\s*`, w, `\b|&&\s*!?`, w, `\b|\b`, w, `\s*(&&|\|\||\?)`]), lines[k])
	not regex.match(concat("", [`\bawait\s+`, w, `\b`]), lines[k])
}

# Local names bound to compare/verify by a named import or destructured
# require: `import { compare } from 'bcryptjs'`, `const { verify: v } = require('argon2')`.
_aliases(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?:import\s*\{([^}]*)\}\s*from|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\()\s*['"](?:bcrypt|bcryptjs|argon2)['"]`, content, -1)
	some part in split(concat(",", [m[1], m[2]]), ",")
	p := trim_space(part)
	kv := regex.split(`\s+as\s+|\s*:\s*`, p)
	trim_space(kv[0]) in {"compare", "verify"}
	n := trim_space(kv[count(kv) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, n)
}

_verify_re(content) := _async_verify if {
	count(_aliases(content)) == 0
} else := concat("", [_async_verify, `|\b(`, concat("|", _aliases(content)), `)\s*\(`])

# The result tested after the call: `compare(a, b) ? x : y`, `verify(...) && ok`.
_suffix_use(c, vre) if regex.match(concat("", [`(`, vre, `)[^;]*?\)\s*(\?[^?.]|&&|\|\|)`]), c)

# A condition opened on the line above: `if (` / `user &&` / `||`.
_cond_above(lines, i) if {
	i > 0
	k := max([0, i - 1])
	regex.match(`(\bif\s*\(|\bwhile\s*\(|&&|\|\||!|\?)\s*$`, _code(lines[k]))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	regex.match(`compare|verify`, content)
	vre := _verify_re(content)
	regex.match(vre, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	c := _code(line)
	parts := regex.split(vre, c)
	count(parts) > 1
	prefix := parts[0]
	not regex.match(`[.$]\s*$`, prefix)
	not regex.match(`\b(function|async)\s*$`, prefix)
	not _awaited(prefix)
	not _handled(lines, i)
	_tested(lines, i, prefix, c, vre)
	finding := _finding(path, i, line, "bcrypt.compare()/argon2.verify() returns a Promise, and a Promise is always truthy: this check accepts every password (and a negated check never rejects). Await the result (if (await bcrypt.compare(pw, hash))) or use the callback form")
}

# ── Re-hash with a fresh salt, then compare ──────────────────────────────

_fresh_hash := {
	"py": `\bbcrypt\.hashpw\(.*gensalt\(|\bgenerate_password_hash\(|\bmake_password\(\s*[^,()]+\)|\b(pwd_context|pwd_ctx|crypt_context|password_context|ph|hasher|password_hasher|argon2|pbkdf2_sha256|bcrypt_sha256|sha256_crypt|sha512_crypt)\.hash\(`,
	"java": `\b\w*[Ee]ncoder\(?\)?\.encode\(|\bBCrypt\.hashpw\(.*gensalt\(`,
	"js": `\b(bcrypt|bcryptjs)\.hash(Sync)?\(\s*[^,]+,\s*(\d+|\w*[Rr]ounds\w*|\w*ROUNDS\w*|\w*[Ss]alt[Rr]ounds|(bcrypt|bcryptjs)\.genSaltSync\()`,
}

_needle := {"py": "hash", "java": "ncode", "js": "hash"}

_needle2 := {"py": "make_password", "java": "hashpw", "js": "hash"}

_has_needle(lang, s) if contains(s, _needle[lang])

_has_needle(lang, s) if contains(s, _needle2[lang])

_cmp := `===?|!==?|\.equals\(`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(lang, content)
	regex.match(_fresh_hash[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_has_needle(lang, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_fresh_hash[lang], c)
	# Two fresh hashes compared with each other test salting, not a password.
	count(regex.find_n(_fresh_hash[lang], c, 2)) < 2
	some k in _compared_at(lines, i, c)
	finding := _finding(path, k, lines[k], "The submitted password is hashed again with a new random salt and compared with the stored hash; a salted hash never repeats, so this check can never succeed and tends to be worked around. Use the library's verifier: bcrypt.checkpw / check_password_hash / passwordEncoder.matches / await bcrypt.compare")
}

_compared_at(lines, i, c) := _same_line(c, i) | _later(lines, i, c)

# Compared on the same line, after the hash call.
_same_line(c, i) := {i} if {
	parts := regex.split(`\b(hashpw|generate_password_hash|make_password|hash|hashSync|encode)\(`, c)
	count(parts) > 1
	regex.match(_cmp, concat("", array.slice(parts, 1, count(parts))))
	not regex.match(`^\s*(const|let|var)?\s*[\w.]+\s*=\s*[^=]`, c)
} else := set()

# Assigned to a name that a comparison within five lines uses.
_later(lines, i, c) := {k |
	w := helpers.assigned_first(c)
	not contains(w, ".")
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 5]))
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`\b`, w, `\s*(===?|!==?)|(===?|!==?)\s*`, w, `\b|\b`, w, `\.equals\(|\.equals\(\s*`, w, `\s*\)`]), lines[k])
	# A null or empty check on the new hash is not a password comparison.
	not regex.match(concat("", [`\b`, w, `\s*(===?|!==?)\s*(null|undefined|None|nil|''|""|\x60\x60)(\W|$)|(null|undefined|None)\s*(===?|!==?)\s*`, w, `\b`]), lines[k])
}
