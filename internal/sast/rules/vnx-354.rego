# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_354

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-354",
	"name": "Integrity check value validated so that a missing, partial or truncated value passes",
	"description": "A checksum, MAC or signature is computed but the comparison that validates it can be passed without the right value. Reported in Python, JavaScript/TypeScript and Java: (1) verification that runs only when the supplied value is present, so omitting it skips the check: if sig and not hmac.compare_digest(...), if sig is not None and not hmac.compare_digest(...), if checksum and actual != checksum, if (sig && sig !== expected), if (signature.length && !crypto.timingSafeEqual(...)), if (signature != null && !MessageDigest.isEqual(...)), where the tested name is a signature, MAC, HMAC, digest, hash, checksum, integrity, md5/sha1/sha256-style or crc32 value, the branch rejects (raise, throw, abort, a 4xx status, return false) within three lines, and no line in the eight above rejects the value when it is missing; (2) a prefix, suffix or substring test against a computed digest (assigned from hexdigest()/digest()/hmac.new/createHmac/createHash/Mac.doFinal/MessageDigest within the 20 lines above, or computed inline): computed.startswith(provided), digest.endsWith(x), x in digest, digest.includes(x)/indexOf(x)/contains(x), which an empty or short value satisfies; (3) a digest truncated before it is compared (hexdigest()[:8] == tag, hash.slice(0, 8) === x, hash.substring(0, 8).equals(x)). Not reported: change detection whose branch does work instead of rejecting (if (lastHash && hash !== lastHash) rebuild()), a value rejected when missing a few lines above (if not sig / sig is None / sig == null / Objects.requireNonNull(sig) / checkNotNull / assert sig), a URL fragment read from location.hash, a positive form (if sig and compare_digest(...): accept), prefix tests against a string literal (sig.startswith('sha256=')), a digest looked up in a collection (digest in known_hashes, hashes.contains(hash)), a truncated digest that is not compared (a short id), location.hash, comments and string literals. Constant-time comparison (VNX-CRYPTO-008) and a discarded verification result (VNX-227) have their own rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-354/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [354],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["integrity-validation", "signature", "hmac", "checksum", "cwe-354"],
}

_lang(path) if regex.match(`\.(py|js|mjs|cjs|jsx|ts|tsx|mts|cts|java)$`, path)

_skip(path) if helpers.is_test_path(path)

_skip(path) if endswith(path, ".min.js")

_gate(c) if contains(c, "igest")

_gate(c) if contains(c, "mac")

_gate(c) if contains(c, "Mac")

_gate(c) if contains(c, "MAC")

_gate(c) if contains(c, "createHash")

_gate(c) if contains(c, "ignature")

_gate(c) if contains(c, "hecksum")

_gate(c) if contains(c, "integrity")

# A name that holds an integrity value: the expression ends with, or its last
# segment names, a signature, MAC, digest, hash, checksum or integrity value.
_integrity_word := `(?i)(?:sig|signature|hmac|mac|digest|hash|checksum|integrity|md5|sha1|sha224|sha256|sha384|sha512|crc32)s?(?:_?(?:header|value|hex|str|string|bytes|buf))?$`

_integrity_expr(expr) if {
	segs := [s | some s in split(expr, "."); s != ""]
	some s in segs
	not regex.match(`(?i)^(location|window|url|document)$`, segs[0])
	regex.match(_integrity_word, regex.replace(s, `\[.*$|\(.*$`, ""))
}

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, `""`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	_gate(content)
	regex.match(_optional_gate, content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "if")
	regex.match(_optional_line, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	operand := _optional_operand(code)
	_integrity_expr(operand)
	name := split(operand, ".")[0]
	not _rejected_when_missing(lines, i, name)
	not _from_location_hash(lines, i, name)
	_rejects(lines, i)
	finding := _finding(path, i, line, sprintf("Integrity check on %s runs only when the value is present: a request that omits it skips verification. Reject a missing value first", [operand]))
}

# ── (1) verification guarded by the value's presence ────────────────────

# Python: if sig and not compare_digest(...) / if sig and sig != x / x != sig
_optional_operand(code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:el)?if\s+([A-Za-z_][\w\.]*)(?:\s+is\s+not\s+None)?\s+and\s+(.*)$`, code, 1)
	count(m) > 0
	_negative_check(m[0][1], m[0][2])
}

# JavaScript: if (sig && sig !== x) / if (sig.length && !timingSafeEqual(...))
# Java: if (sig != null && !MessageDigest.isEqual(...)) / !sig.equals(x)
_optional_operand(code) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\}\s*else\s+)?if\s*\(\s*([A-Za-z_$][\w\.$]*)\s*(?:!==?\s*(?:null|undefined|""))?\s*&&\s*(.*)$`, code, 1)
	count(m) > 0
	_negative_check(m[0][1], m[0][2])
}

_negative_check(_, rest) if regex.match(`^\(?\s*(?:not\s+|!\s*)[\w\.$]*?(?:compare_digest|timingSafeEqual|isEqual|verify\w*|check\w*|equals(?:IgnoreCase)?|compare\w*|Equal)\s*\(`, rest)

_negative_check(op, rest) if {
	base := regex.replace(op, `\.length$`, "")
	regex.match(concat("", [`^\(?\s*`, _q(base), `\s*!==?\s*[\w\.$\(\)\[\]]+`]), rest)
}

_negative_check(op, rest) if {
	base := regex.replace(op, `\.length$`, "")
	regex.match(concat("", [`^\(?\s*[\w\.$\(\)\[\]]+\s*!==?\s*`, _q(base), `\b`]), rest)
}

_negative_check(op, rest) if {
	base := regex.replace(op, `\.length$`, "")
	regex.match(concat("", [`^\(?\s*!\s*`, _q(base), `\.equals\(`]), rest)
}

_q(s) := replace(replace(s, ".", `\.`), "$", `\$`)

# A line in the eight above rejects the value when it is missing.
_rejected_when_missing(lines, i, name) if {
	start := max([0, i - 8])
	i - 1 >= start
	some j in numbers.range(start, i - 1)
	l := lines[j]
	contains(l, name)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`(?:if\s+not\s+`, _q(name), `\b|`, _q(name), `\s+is\s+None|!\s*`, _q(name), `\s*(?:\)|\|\|)|`, _q(name), `\s*===?\s*(?:null|undefined|""|'')\s*(?:[^?\s]|$)|`, _q(name), `\.isEmpty\(\)|len\(\s*`, _q(name), `\s*\)\s*==\s*0|`, _q(name), `\s+is\s+not\s+None\s+else|(?:requireNonNull|checkNotNull|requireNonEmpty)\(\s*`, _q(name), `\b|^\s*assert\s+`, _q(name), `\b)`]), l)
}

# The guarded branch rejects (raise/throw/abort/4xx/return false) on the
# condition's line or within the three lines after it: a verification, not
# change detection (if (lastHash && hash !== lastHash) rebuild()).
_reject_re := `(?:\braise\b|\bthrow\b|\babort\s*\(|\breject\w*\s*\(|\bdeny\w*\s*\(|\bForbidden\b|\bUnauthorized\b|status\(\s*4\d\d|sendStatus\(\s*4\d\d|\b40[013]\b|\breturn\s+(?:False|false|null|None|nil)\b|\bError\b|Exception\b)`

_rejects(lines, i) if {
	some j in numbers.range(i, min([count(lines) - 1, i + 3]))
	not helpers.is_comment_line(lines[j])
	regex.match(_reject_re, _code(lines[j]))
}

# The "hash" is the URL fragment (window.location.hash), not a digest.
_from_location_hash(lines, i, name) if {
	start := max([0, i - 8])
	some j in numbers.range(start, i)
	regex.match(concat("", [`\b`, _q(name), `\s*=\s*[\w\.]*location\.hash\b`]), lines[j])
}

# ── (2) prefix / suffix / substring test against a computed digest ──────

_digest_src := `hexdigest\(|\.digest\(|hmac\.new\(|\bHMAC\(|createHmac\(|createHash\(|doFinal\(|MessageDigest\b|DigestUtils\.|Hashing\.|hashlib\.`

_inline_digest := `(?:hexdigest\(\)|\.digest\(\s*(?:["']\w+["'])?\s*\)|doFinal\([^)]*\))`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	_gate(content)
	regex.match(_digest_src, content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:startswith|endswith|startsWith|endsWith|includes|indexOf|contains|regionMatches)\(|^\s*(?:if|elif|return|assert|while)\b[^#]*\sin\s|=\s*[^=#]*\sin\s|\[\s*:\s*\d+\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	names := helpers.tainted_names(lines, i, 20, _digest_src)
	msg := _weak_compare(code, names)
	finding := _finding(path, i, line, msg)
}

_partial_msg := "A computed digest/MAC is validated with a prefix, suffix or substring test: an empty or shortened value passes. Compare the whole value with hmac.compare_digest / crypto.timingSafeEqual / MessageDigest.isEqual"

_trunc_msg := "A computed digest/MAC is truncated before it is compared, so only a few bytes of the integrity value are checked. Compare the full value in constant time"

# digest.startswith(x) / x.startswith(digest), x not a literal
_weak_compare(code, names) := _partial_msg if {
	some n in names
	regex.match(concat("", [`\b`, n, `\s*\.\s*(?:startswith|endswith|startsWith|endsWith)\(\s*[A-Za-z_$]`]), code)
}

_weak_compare(code, names) := _partial_msg if {
	some n in names
	regex.match(concat("", [`\b[A-Za-z_$][\w\.$]*\s*\.\s*(?:startswith|endswith|startsWith|endsWith)\(\s*`, n, `\s*\)`]), code)
}

# substring search inside the digest: digest.includes(x), x in digest
_weak_compare(code, names) := _partial_msg if {
	some n in names
	regex.match(concat("", [`\b`, n, `\s*\.\s*(?:includes|indexOf|contains)\(\s*[A-Za-z_$]`]), code)
}

_weak_compare(code, names) := _partial_msg if {
	some n in names
	regex.match(concat("", [`\b[A-Za-z_][\w\.]*\s+in\s+`, n, `\s*(?:[:\)]|$|\s+(?:and|or)\b)`]), code)
	not regex.match(concat("", [`\bfor\s+\w+\s+in\s+`, n, `\b`]), code)
}

# inline: hmac.new(...).hexdigest().startswith(x)
_weak_compare(code, _) := _partial_msg if {
	regex.match(concat("", [_inline_digest, `\s*\.\s*(?:startswith|endswith|startsWith|endsWith|includes|indexOf|contains)\(\s*[A-Za-z_$]`]), code)
}

# truncated then compared
_weak_compare(code, names) := _trunc_msg if {
	some n in names
	regex.match(concat("", [`\b`, n, `\s*(?:\[\s*:\s*\d+\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,\s*\d+\s*\))\s*(?:===?|!==?|\.equals\()`]), code)
}

_weak_compare(code, names) := _trunc_msg if {
	some n in names
	regex.match(concat("", [`(?:===?|!==?)\s*`, n, `\s*(?:\[\s*:\s*\d+\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,)`]), code)
}

_weak_compare(code, _) := _trunc_msg if {
	regex.match(concat("", [_inline_digest, `\s*(?:\[\s*:\s*\d+\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,\s*\d+\s*\))\s*(?:===?|!==?|\.equals\()`]), code)
}

# Whole-file and per-line prefilters for (1): an if whose condition is
# `X and ...` / `X && ...` followed by a negative comparison or check.
_optional_gate := `(?m)^\s*(?:\}\s*else\s+)?(?:el)?if\b[^\n]*(?:\sand\s|&&)[^\n]*(?:!=|\bnot\b|!\s*[\w\.$]*\()`

_optional_line := `^\s*(?:\}\s*else\s+)?(?:el)?if\b.*(?:\sand\s|&&).*(?:!=|\bnot\b|!\s*[\w\.$]*\()`
