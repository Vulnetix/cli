# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_324

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-324",
	"name": "Use of a Key Past its Expiration Date",
	"description": "An expired certificate or signed token is accepted instead of rejected, so a key or credential keeps working after the date its issuer set for it to stop. Reported: Java/Kotlin JJWT and auth0 catch blocks (including Java multi-catch and Kotlin catch (e: X)) for CertificateExpiredException, ExpiredJwtException or TokenExpiredException that swallow the exception (empty or log-only body that falls through), return true, or go on to use the expired token's e.getClaims() (Kotlin e.claims); Node.js jsonwebtoken ignoreExpiration: true; a JJWT setAllowedClockSkewSeconds/clockSkewSeconds or auth0 acceptLeeway/acceptExpiresAt/acceptNotBefore of MAX_VALUE or a literal of at least 86400 seconds; Python PyJWT/python-jose options with 'verify_exp': False or dict(verify_exp=False); Ruby ruby-jwt verify_expiration: false; and C/C++ OpenSSL verify callbacks that return 1 or reset the error to X509_V_OK for X509_V_ERR_CERT_HAS_EXPIRED or X509_V_ERR_CERT_NOT_YET_VALID, and X509_V_FLAG_NO_CHECK_TIME set on a verify parameter or store. Not reported: a catch block that rethrows, returns false/null or a 401/403 response (reading e.getClaims() only to log is fine), ignoreExpiration: false and verify_exp: True, the names in comments, test files (decoding an expired fixture is normal), and Go, which VNX-GO-032 covers. Long certificate validity periods are a policy choice and are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-324/",
	"languages": ["java", "kotlin", "node", "python", "ruby", "c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [324],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["key-past-expiry", "cwe-324", "jwt", "certificate"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── one-line option shapes ───────────────────────────────────────────────

_opt_re(path) := `(^|[{,(\s])ignoreExpiration\s*:\s*true\b` if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_opt_re(path) := `['"]verify_exp['"]\s*:\s*False\b|(^|[(,\s])verify_exp\s*=\s*False\b` if endswith(path, ".py")

_opt_re(path) := `(^|[{,(\s])(verify_expiration:|:verify_expiration\s*=>)\s*false\b` if endswith(path, ".rb")

_opt_word(path) := "ignoreExpiration" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_opt_word(path) := "verify_exp" if endswith(path, ".py")

_opt_word(path) := "verify_expiration" if endswith(path, ".rb")

findings contains finding if {
	some path, content in input.file_contents
	word := _opt_word(path)
	contains(content, word)
	not helpers.is_test_path(path)
	re := _opt_re(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, word)
	not helpers.is_comment_line(line)
	regex.match(re, line)
	finding := _finding(path, i, line, "Token expiry verification is disabled, so an expired token is accepted; keep expiry checks on and refresh the token instead")
}

# ── Java/Kotlin: a clock skew or leeway so large expiry never bites ─────

# MAX_VALUE, or a literal of at least one day in seconds (86400).
_skew_re := `\.(setAllowedClockSkewSeconds|clockSkewSeconds|acceptExpiresAt|acceptLeeway|acceptNotBefore)\(\s*(Long\.MAX_VALUE|Integer\.MAX_VALUE|Long\.MAX_VALUE\s*/\s*\d+|(?:8[6-9]\d{3}|9\d{4}|\d{6,})L?)\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	regex.match(`\.(setAllowedClockSkewSeconds|clockSkewSeconds|acceptExpiresAt|acceptLeeway|acceptNotBefore)\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".")
	not helpers.is_comment_line(line)
	regex.match(_skew_re, line)
	finding := _finding(path, i, line, "The token's expiry is accepted with a clock skew or leeway of a day or more, so an expired token keeps working; keep the allowance to seconds or minutes")
}

# ── Java: catch block that accepts the expired certificate/token ────────

_catch_re := `\bcatch\s*\(\s*(?:final\s+)?(?:[\w.]+\s*\|\s*)*(?:java\.security\.cert\.|io\.jsonwebtoken\.|com\.auth0\.jwt\.exceptions\.)?(CertificateExpiredException|ExpiredJwtException|TokenExpiredException)(?:\s*\|\s*[\w.]+)*\s+(\w+)\s*\)`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Body lines of the catch block opened on line i (bounded to 15 lines).
_body(lines, i) := [] if regex.match(`\{\s*\}\s*$`, lines[i])

_body(lines, i) := body if {
	not regex.match(`\{\s*\}\s*$`, lines[i])
	ind := _indent(lines[i])
	end := min([count(lines) - 1, i + 15])
	i + 1 <= end
	closers := [k |
		some k in numbers.range(i + 1, end)
		_indent(lines[k]) <= ind
		startswith(trim_left(lines[k], " \t"), "}")
	]
	count(closers) > 0
	body := [l | some k in numbers.range(i + 1, closers[0] - 1); l := lines[k]; not helpers.is_comment_line(l)]
}

_rejects(text) if regex.match(`\bthrow\b`, text)

_rejects(text) if regex.match(`\breturn\s+(false|null|Optional\.empty\(\)|Mono\.error|ResponseEntity\.status\(\s*(HttpStatus\.)?(UNAUTHORIZED|FORBIDDEN|4\d\d)|[^;]*\b40[13]\b)`, text)

_rejects(text) if regex.match(`\b(sendError|setStatus|UNAUTHORIZED|FORBIDDEN|SC_UNAUTHORIZED|SC_FORBIDDEN)\b`, text)

# The block accepts the expired value: it uses its claims outside a log call,
# returns true, or returns nothing at all (falls through).
_accepts(body, v) if {
	some l in body
	regex.match(concat("", [`\b`, v, `\.(getClaims\(\)|claims\b)`]), l)
	not regex.match(`\b(log|logger|LOG|LOGGER)\.\w+\(|System\.(out|err)\.print`, l)
}

_accepts(body, _) if {
	some l in body
	regex.match(`\breturn\s+true\b`, l)
}

_accepts(body, _) if {
	not _any_return(body)
}

_any_return(body) if {
	some l in body
	regex.match(`\breturn\b`, l)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	contains(content, "Expired")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	c := _catch(line)
	v := c[1]
	body := _body(lines, i)
	text := concat("\n", body)
	not _rejects(text)
	_accepts(body, v)
	finding := _finding(path, i, line, sprintf("%s is caught and the expired certificate or token is accepted; reject it (rethrow or return an authentication failure)", [c[0]]))
}

# [exception, variable] for a Java `catch (X e)` or a Kotlin `catch (e: X)`.
_catch(line) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(_catch_re, line, 1)
	count(m) > 0
}

_catch(line) := [m[0][2], m[0][1]] if {
	not regex.match(_catch_re, line)
	m := regex.find_all_string_submatch_n(`\bcatch\s*\(\s*(\w+)\s*:\s*(?:java\.security\.cert\.|io\.jsonwebtoken\.|com\.auth0\.jwt\.exceptions\.)?(CertificateExpiredException|ExpiredJwtException|TokenExpiredException)\s*\)`, line, 1)
	count(m) > 0
}

# ── C/C++: OpenSSL verify callback that accepts an expired certificate ──

_c_exts := {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

_x509_re := `(==\s*X509_V_ERR_CERT_(HAS_EXPIRED|NOT_YET_VALID)\b|\bX509_V_ERR_CERT_(HAS_EXPIRED|NOT_YET_VALID)\s*==|\bcase\s+X509_V_ERR_CERT_(HAS_EXPIRED|NOT_YET_VALID)\s*:)`

findings contains finding if {
	some path, content in input.file_contents
	some ext in _c_exts
	endswith(path, ext)
	contains(content, "X509_V_ERR_CERT_")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "X509_V_ERR_CERT_")
	not helpers.is_comment_line(line)
	regex.match(_x509_re, line)
	window := helpers.code_window(lines, i, 0, 5)
	regex.match(`\breturn\s+(1|true|TRUE)\s*;|X509_STORE_CTX_set_error\s*\([^,]+,\s*X509_V_OK\s*\)`, window)
	finding := _finding(path, i, line, "The certificate verify callback accepts an expired or not-yet-valid certificate; return preverify_ok for these errors")
}

# X509_V_FLAG_NO_CHECK_TIME turns the validity-period check off entirely.
findings contains finding if {
	some path, content in input.file_contents
	some ext in _c_exts
	endswith(path, ext)
	contains(content, "X509_V_FLAG_NO_CHECK_TIME")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "X509_V_FLAG_NO_CHECK_TIME")
	not helpers.is_comment_line(line)
	regex.match(`\b(X509_VERIFY_PARAM_set_flags|X509_STORE_set_flags|X509_STORE_CTX_set_flags)\s*\(`, line)
	finding := _finding(path, i, line, "X509_V_FLAG_NO_CHECK_TIME disables the certificate validity-period check, so expired certificates are accepted; remove the flag")
}
