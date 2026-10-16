# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_223

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-223",
	"name": "Omission of Security-relevant Information",
	"description": "Python code throws away the record of a security event, so a forged token, a bad signature or a refused permission leaves no trace for detection or investigation (and, when the handler only passes, the check may fail open). CWE-223 is a property of what a system records; the rule reports the concrete places where code discards it. Reported: an except clause whose whole body is pass, ... or continue, when the exception is a security one (jwt PyJWTError/InvalidTokenError/ExpiredSignatureError/DecodeError, itsdangerous BadSignature/SignatureExpired, cryptography InvalidSignature, Django PermissionDenied/SuspiciousOperation, DRF AuthenticationFailed, CSRFError, argon2 VerifyMismatchError and similar) or when the try block performs a verification (jwt.decode, .verify(), verify_*(), check_password, authenticate, hmac.compare_digest, .unsign, bcrypt.checkpw, validate_csrf, has_perm, check_permissions); the same exceptions, or any exception around such a verification, silenced by with contextlib.suppress(...); logging.disable() with no argument or a level above DEBUG; a security, auth, audit, access or login logger set disabled = True (directly, or through the variable it was assigned to a few lines above); and Django LOGGING routing a django.security logger to the null handler (or to no handler) with propagate False. Not reported: handlers that log, raise or return a failure, a continue that tries the next key in a loop which raises or logs once every key has failed (key rotation), swallowed exceptions unrelated to security (FileNotFoundError around os.remove, a bare except around conn.close()), logging.disable(logging.NOTSET), django.security sent to real handlers, comments and test code (including conftest.py).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-223/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [223],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["omission-logging", "security-logging", "error-handling", "cwe-223"],
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

_msg_swallow := "A failed security check is swallowed without a trace: the rejected token, signature or permission is neither logged nor reported, and execution continues. Log the event (who, what, from where) and fail closed"

_msg_logging := "Security-relevant logging is switched off: attacks and failed checks will leave no record. Keep security and audit loggers enabled and route them to a real handler"

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)conftest\.py$`, path)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_sec_exc := `\b(PyJWTError|TokenError|InvalidTokenError|ExpiredSignatureError|DecodeError|InvalidSignatureError|InvalidAudienceError|InvalidIssuerError|ImmatureSignatureError|InvalidSignature|BadSignature|BadTimeSignature|SignatureExpired|BadData|BadPayload|PermissionDenied|SuspiciousOperation|DisallowedHost|AuthenticationFailed|NotAuthenticated|InvalidToken|CSRFError|VerifyMismatchError|VerificationError|InvalidHash|JWTError|JWSError|ExpiredSignature|InvalidKey|Unauthorized|Forbidden)\b`

_verify := `\bjwt\.decode\s*\(|\.verify(_\w+)?\s*\(|(^|[^\w.])verify_\w+\s*\(|\bcheck_password\s*\(|\bauthenticate\s*\(|\bcompare_digest\s*\(|\.unsign\s*\(|\bcheckpw\s*\(|\bvalidate_csrf\s*\(|\bhas_perms?\s*\(|\bcheck_(object_)?permissions?\s*\(|\bdecode_token\s*\(`

_except := `^(\s*)except\b([^:]*):\s*((pass|\.\.\.|continue)\s*)?(#.*)?$`

_silent := `^\s*(pass|\.\.\.|continue)\s*(#.*)?$`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "except")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "except")
	m := regex.find_all_string_submatch_n(_except, line, 1)
	count(m) > 0
	_silent_body(lines, i, m[0][4])
	_security_related(lines, i, m[0][2])
	not _fails_after_loop(lines, i, m[0][4])
	f := _finding(path, i, line, _msg_swallow)
}

# with suppress(BadSignature): data = s.loads(cookie) is the same swallow,
# as is suppress(Exception) around a verification.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "suppress(")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "suppress(")
	m := regex.find_all_string_submatch_n(`^\s*with\s+(?:contextlib\.)?suppress\s*\(([^)]*)\)\s*:`, line, 1)
	count(m) > 0
	_suppress_security(lines, i, m[0][1])
	f := _finding(path, i, line, _msg_swallow)
}

_suppress_security(_, _, exc) if regex.match(_sec_exc, exc)

_suppress_security(lines, i, _) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	l := lines[k]
	_indent(l) > _indent(lines[i])
	not helpers.is_comment_line(l)
	regex.match(_verify, l)
}

# for key in keys: try: return jwt.decode(...) except ...: continue
# followed, once the loop ends, by a raise or a log line: trying each key in
# turn and failing when none matches is not a swallowed failure.
_fails_after_loop(lines, i, inline) if {
	_is_continue(lines, i, inline)
	ie := _indent(lines[i])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	l := lines[k]
	trim_space(l) != ""
	_indent(l) < ie
	regex.match(`^\s*(raise\b|(log|logger|logging|LOG|LOGGER|_log|_logger)\.\w+\s*\()`, l)
}

_is_continue(_, _, "continue")

_is_continue(lines, i, "") if {
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*continue\b`, lines[j])
}

# except X: pass  (single line)
_silent_body(_, _, inline) if inline != ""

_silent_body(lines, i, "") if {
	j := helpers.next_code_index(lines, i, 3)
	regex.match(_silent, lines[j])
	_indent(lines[j]) > _indent(lines[i])
	not _more_body(lines, i, j)
}

# Another statement in the same handler after the pass.
_more_body(lines, i, j) if {
	k := helpers.next_code_index(lines, j, 4)
	_indent(lines[k]) > _indent(lines[i])
}

_security_related(_, _, exc) if regex.match(_sec_exc, exc)

_security_related(lines, i, _) if {
	t := _try_line(lines, i)
	some k in helpers.span(t + 1, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_verify, l)
}

# The try: this except belongs to, at the same indent, at most 15 lines up.
_try_line(lines, i) := t if {
	ie := _indent(lines[i])
	cands := [k |
		some k in numbers.range(max([0, i - 15]), i - 1)
		regex.match(`^\s*try\s*:`, lines[k])
		_indent(lines[k]) == ie
	]
	count(cands) > 0
	t := max(cands)
	t + 1 <= i - 1
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "logging")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "disable")
	not helpers.is_comment_line(line)
	_disables_logging(line)
	f := _finding(path, i, line, _msg_logging)
}

_disables_logging(line) if {
	m := regex.find_all_string_submatch_n(`\blogging\.disable\s*\(\s*([^)]*?)\s*\)`, line, 1)
	count(m) > 0
	not regex.match(`^((logging\.)?(NOTSET|DEBUG)|0|10)$`, m[0][1])
}

_disables_logging(line) if regex.match(`(?i)getLogger\(\s*["'][^"']*(security|auth|audit|access|login)[^"']*["']\s*\)\.disabled\s*=\s*True`, line)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "django.security")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "django.security")
	not helpers.is_comment_line(line)
	regex.match(`["']django\.security(\.\w+)?["']\s*:\s*\{`, line)
	window := concat("\n", array.slice(lines, i, min([count(lines), i + 5])))
	block := split(window, "}")[0]
	regex.match(`["']handlers["']\s*:\s*\[\s*(["']null["']\s*,?\s*)?\]`, block)
	regex.match(`["']propagate["']\s*:\s*False`, block)
	f := _finding(path, i, line, _msg_logging)
}

# audit_log = logging.getLogger("app.audit") ... audit_log.disabled = True
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, ".disabled")
	contains(content, "getLogger")
	not _skip(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "getLogger")
	m := regex.find_all_string_submatch_n(`(?i)^\s*([A-Za-z_][\w.]*)\s*=\s*logging\.getLogger\(\s*["'][^"']*(security|auth|audit|access|login)[^"']*["']\s*\)`, al, 1)
	count(m) > 0
	v := m[0][1]
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 10]))
	line := lines[i]
	contains(line, ".disabled")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`^\s*`, replace(v, ".", `\.`), `\.disabled\s*=\s*True\b`]), line)
	f := _finding(path, i, line, _msg_logging)
}
