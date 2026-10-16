# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_347

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-347",
	"name": "Improper Verification of Cryptographic Signature",
	"description": "A signature or MAC is checked but the outcome is thrown away, so data with a forged signature is processed as if it were genuine. Reported: a verification whose boolean result (or error) is discarded as a bare statement: Java java.security.Signature verify() on a variable declared or created as a Signature; Go ed25519.Verify, ecdsa.Verify/VerifyASN1, hmac.Equal, subtle.ConstantTimeCompare and rsa.VerifyPKCS1v15/VerifyPSS (bare or assigned to _); Node.js verify() on a createVerify() object, crypto.verify() without a callback, crypto.timingSafeEqual() (also imported by name from crypto), (await) crypto.subtle.verify() and the jws package's jws.verify(), which returns a boolean; Python hmac.compare_digest()/secrets.compare_digest(); and a signature failure that is caught and swallowed: Python `except InvalidSignature/BadSignature/BadSignatureError/InvalidSignatureError` (or a bare/Exception handler around a .verify() call, on a receiver named for a key, signature, verifier, token, JWT, MAC or certificate, in the six lines above; smtp.verify() and service.verify() are not signature checks) whose body is only pass, ... or a log call, and Java `catch (SignatureException | SignatureVerificationException | InvalidSignatureException | JWTVerificationException | JwtException ...)` (or Exception/GeneralSecurityException around a .verify() call) whose block is empty or only logs. Not reported: results that are tested, assigned, returned or passed on (including an assignment split over two lines), calls that throw on failure (jsonwebtoken jwt.verify, auth0 JWTVerifier.verify, cryptography's key.verify inside a handler that raises or returns), crypto.verify with a callback, handlers that raise, return or rethrow, a Python handler whose try body only assigns the verified value to names set to None/False/empty just above the try (the code fails closed: user_id = None; try: user_id = s.loads(v) except BadSignature: pass; a default holding the unverified input is still reported), empty catches around code that verifies nothing, comments and string literals. Disabled TLS certificate validation is VNX-CRYPTO-005's concern and disabled JWT verification VNX-JWT-001's.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-347/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [347],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["signature", "crypto", "cwe-347"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_is_js(path) if {
	some e in _js_exts
	endswith(path, e)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The previous code line ends a statement, so line i starts one.
_statement_start(lines, i) if i == 0

_statement_start(lines, i) if {
	i > 0
	prev := [j | some j in numbers.range(max([0, i - 4]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(prev) == 0
}

_statement_start(lines, i) if {
	i > 0
	prev := [j | some j in numbers.range(max([0, i - 4]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(prev) > 0
	p := trim_space(lines[prev[count(prev) - 1]])
	not regex.match(`(?:=|:=|\(|,|&&|\|\||!|\?|:|\+|\\|\breturn|\band|\bor|\bnot|\bassert|\bawait|=>)$`, p)
}

# The previous code line opens an indented block (def f(...):, if x:, try:).
_statement_start(lines, i) if {
	i > 0
	prev := [j | some j in numbers.range(max([0, i - 4]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(prev) > 0
	regex.match(`^\s*(?:async\s+)?(?:def|class|if|elif|else|for|while|try|except|finally|with)\b[^#]*:\s*$`, lines[prev[count(prev) - 1]])
}

_call_text(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 4])))

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_discard_msg := "The signature/MAC check's result is discarded, so forged data is processed as genuine. Test the result and stop on failure"

_swallow_msg := "A signature verification failure is caught and ignored, so forged data continues as genuine. Reject the input in the handler (raise, return an error or abort)"

# ── Java: Signature.verify() as a bare statement ─────────────────────────
_java_sig_names(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\bSignature\s+([A-Za-z_]\w*)\s*[=;,)]`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:java\.security\.)?Signature\.getInstance\(`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Signature")
	contains(content, ".verify(")
	names := _java_sig_names(content)
	count(names) > 0
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.verify\(`, line, 1)
	count(m) > 0
	m[0][1] in names
	_statement_start(lines, i)
	finding := _finding(path, i, line, _discard_msg)
}

# ── Go: verification call as a bare statement ────────────────────────────
_go_verify_re := `^\s*(?:_\s*=\s*)?(?:ed25519\.Verify|ecdsa\.Verify(?:ASN1)?|hmac\.Equal|subtle\.ConstantTimeCompare|rsa\.Verify(?:PKCS1v15|PSS))\(`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?:ed25519|ecdsa|hmac|subtle|rsa)\.(?:Verify|Equal|ConstantTimeCompare)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_go_verify_re, line)
	_statement_start(lines, i)
	finding := _finding(path, i, line, _discard_msg)
}

# ── Node.js ───────────────────────────────────────────────────────────────
_js_verifier_names(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_$][\w$]*)\s*=\s*(?:crypto\.)?createVerify\(`, content, -1)
} | {"timingSafeEqual" |
	regex.match(`\{[^}]*\btimingSafeEqual\b[^}]*\}\s*(?:=\s*require\(\s*|from\s+)["'](?:node:)?crypto["']`, content)
}

_js_bare(line, names) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_$][\w$]*)\.verify\(`, line, 1)
	count(m) > 0
	m[0][1] in names
}

_js_bare(line, _) if regex.match(`^\s*(?:await\s+)?(?:window\.|globalThis\.|self\.)?crypto\.(?:verify|timingSafeEqual|subtle\.verify)\(`, line)

# The jws package's verify() returns a boolean rather than throwing.
_js_bare(line, _) if regex.match(`^\s*jws\.verify\(`, line)

# timingSafeEqual imported by name: import { timingSafeEqual } from "crypto"
_js_bare(line, names) if {
	"timingSafeEqual" in names
	regex.match(`^\s*timingSafeEqual\(`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`crypto|\bjws\b`, content)
	regex.match(`\.verify\(|timingSafeEqual\(`, content)
	names := _js_verifier_names(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`verify\(|timingSafeEqual\(`, line)
	_js_bare(line, names)
	not regex.match(`=>|\bfunction\b`, _call_text(lines, i))
	_statement_start(lines, i)
	finding := _finding(path, i, line, _discard_msg)
}

# ── Python: compare_digest as a bare statement ───────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "compare_digest(")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(?:hmac|secrets)\.compare_digest\(`, line)
	_statement_start(lines, i)
	finding := _finding(path, i, line, _discard_msg)
}

# ── Python: signature failure swallowed ──────────────────────────────────
_py_sig_exc := `InvalidSignature(?:Error)?|BadSignature(?:Error)?|SignatureVerificationError|BadSignatureError`

_py_except(lines, i) if regex.match(concat("", [`^\s*except\s*\(?[\w.\s,]*\b(?:`, _py_sig_exc, `)\b[\w.\s,]*\)?\s*(?:as\s+\w+\s*)?:\s*$`]), lines[i])

_py_except(lines, i) if {
	regex.match(`^\s*except\s*(?:\(?\s*(?:Exception|BaseException)\s*\)?\s*(?:as\s+\w+\s*)?)?:\s*$`, lines[i])
	w := helpers.code_window(lines, i, 6, 0)
	regex.match(_bare_verify_re, w)
}

_py_log_re := `^\s*(?:[\w.]*log\w*|logger|logging|print|warnings)(?:\.\w+)?\s*\(`

# body is only pass/... (optionally after one log call), then the block ends
_py_swallowed(lines, i) if {
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*(?:pass|\.\.\.)\s*$`, lines[j])
	_py_block_ends(lines, i, j)
}

_py_swallowed(lines, i) if {
	j := helpers.next_code_index(lines, i, 3)
	regex.match(_py_log_re, lines[j])
	_py_block_ends(lines, i, j)
}

_py_block_ends(lines, i, j) if not helpers.next_code_index(lines, j, 4)

_py_block_ends(lines, i, j) if {
	k := helpers.next_code_index(lines, j, 4)
	_indent(lines[k]) <= _indent(lines[i])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?:InvalidSignature|BadSignature|SignatureVerificationError|\.verify\()`, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_space(line), "except")
	_py_except(lines, i)
	_py_swallowed(lines, i)
	not _py_fails_closed(lines, i)
	finding := _finding(path, i, line, _swallow_msg)
}

# The try body only assigns the verified value to names that were set to
# None/False/empty just above the try: on a bad signature the name keeps that
# empty default, so the code fails closed (user_id = None; try: user_id =
# s.loads(v) except BadSignature: pass). A default holding the unverified
# input (payload = signed) is still reported.
_py_fails_closed(lines, i) if {
	ind := _indent(lines[i])
	tries := [t | some t in numbers.range(max([0, i - 8]), i - 1); regex.match(`^\s*try\s*:\s*$`, lines[t]); _indent(lines[t]) == ind]
	count(tries) > 0
	t := tries[count(tries) - 1]
	body := [l | some k in helpers.span(t + 1, i - 1); l := lines[k]; trim_space(l) != ""; not helpers.is_comment_line(l)]
	count(body) > 0
	every l in body {
		regex.match(`^\s*[A-Za-z_]\w*\s*=[^=]`, l)
	}
	every l in body {
		v := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*=`, l, 1)[0][1]
		_empty_default(lines, t, v)
	}
}

_empty_default(lines, t, v) if {
	some j in numbers.range(max([0, t - 5]), t - 1)
	regex.match(concat("", [`^\s*`, v, `\s*=\s*(?:None|False|""|''|\{\}|\[\]|0)\s*$`]), lines[j])
}

# ── Java: signature failure swallowed ────────────────────────────────────
_java_sig_exc := `SignatureException|SignatureVerificationException|InvalidSignatureException|JWTVerificationException|JwtException`

_java_catch(lines, i) if regex.match(concat("", [`\bcatch\s*\(\s*(?:final\s+)?[\w.\s|]*\b(?:`, _java_sig_exc, `)\b[\w.\s|]*\)`]), lines[i])

_java_catch(lines, i) if {
	regex.match(`\bcatch\s*\(\s*(?:final\s+)?(?:java\.lang\.)?(?:Exception|Throwable|GeneralSecurityException)\s+\w+\s*\)`, lines[i])
	w := helpers.code_window(lines, i, 6, 0)
	regex.match(_bare_verify_re, w)
}

# A verify call used as a statement: the code relies on it throwing. A result
# assigned or returned inside the try is carried past the handler instead.
# The receiver must name a key, signature, verifier, token or MAC: smtp.verify()
# (SMTP VRFY) or mailService.verify() are not signature checks.
_bare_verify_re := `(?m)^\s*(?:[A-Za-z_]\w*\.)*\w*(?i:key|sig|verif|jw[st]|mac|cert|token)\w*\.verify\(`

_java_log_re := `^\s*(?:[\w.]*(?:log|LOG|Log|logger|LOGGER)\w*\.\w+|System\.(?:out|err)\.print\w*|\w+\.printStackTrace)\s*\(`

_java_swallowed(lines, i) if regex.match(`\)\s*\{\s*\}`, lines[i])

_java_swallowed(lines, i) if {
	regex.match(`\)\s*\{\s*$`, lines[i])
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*\}`, lines[j])
}

_java_swallowed(lines, i) if {
	regex.match(`\)\s*\{\s*$`, lines[i])
	j := helpers.next_code_index(lines, i, 3)
	regex.match(_java_log_re, lines[j])
	k := helpers.next_code_index(lines, j, 3)
	regex.match(`^\s*\}`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "catch")
	regex.match(`Signature|JWTVerification|JwtException|\.verify\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	not helpers.is_comment_line(line)
	_java_catch(lines, i)
	_java_swallowed(lines, i)
	finding := _finding(path, i, line, _swallow_msg)
}
