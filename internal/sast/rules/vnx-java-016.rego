package vulnetix.rules.vnx_java_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-016",
	"name": "Java weak PRNG (java.util.Random) used for security-sensitive value",
	"description": "A value drawn from a non-cryptographic generator is used as a secret: new java.util.Random().nextX(), a Random field or local created with new Random(...) and drawn with next*/ints/longs/doubles, ThreadLocalRandom.current().nextX(), Math.random() or Apache Commons RandomStringUtils.random*/randomAlphanumeric/randomNumeric (static methods built on java.util.Random). Reported when the draw is used for a token, nonce, password, salt, OTP/PIN, CSRF token, remember-me or session identifier, API/secret key or IV: the draw's own statement names such an identifier, the draw is stored straight into a Cookie, a session attribute or value, or a response header, the variable it assigns (or the buffer nextBytes fills) flows within the next six lines, directly or through one more assignment, into such an identifier or store, or the draw (or a weak Random handed to a helper) is returned from a method named for a secret (newSessionId, generateToken, createPasswordReset). Not reported: java.security.SecureRandom (including a SecureRandom held in a Random-typed variable) and RandomStringUtils.secure()/secureStrong(), randomness for jitter, shuffling, sampling, load balancing, colours and other non-secret uses, test code, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-016/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [330],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "weak-random", "java"],
}

_msg := "Security-sensitive value drawn from a predictable generator (java.util.Random, ThreadLocalRandom, Math.random or RandomStringUtils); use java.security.SecureRandom for tokens, session IDs, nonces, passwords, salts and keys"

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_inline_draw_re := `\bnew\s+(?:java\.util\.)?Random\s*\([^()]*\)\s*\.\s*(?:next\w*|ints|longs|doubles)\s*\(|\bMath\.random\s*\(\s*\)|\bThreadLocalRandom\s*\.\s*current\s*\(\s*\)\s*\.\s*(?:next\w*|ints|longs|doubles)\s*\(|\bRandomStringUtils\s*\.\s*random\w*\s*\(`

# Variables created as a plain java.util.Random.
_weak_vars(lines) := {m[1] |
	some l in lines
	contains(l, "Random")
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*(?:new\s+(?:java\.util\.)?Random\s*\(|ThreadLocalRandom\s*\.\s*current\s*\(\s*\)\s*;)`, l, -1)
}

_var_draw_re(vars) := concat("", [`\b(?:`, concat("|", vars), `)\s*\.\s*(?:next\w*|ints|longs|doubles)\s*\(`])

# Identifiers that name a secret. Matched on code with strings blanked.
_sensitive_re := `(?i)(?:token|nonce|secret|passw|passphrase|\bpwd\b|salt|\botp\b|\bpin(?:code)?\b|csrf|xsrf|remember|session_?id|sessid|session_?key|api_?key|access_?key|private_?key|signing_?key|encryption_?key|aes_?key|hmac_?key|secret_?key|auth_?code|reset_?code|verification_?code|activation|captcha|\biv\b|credential)`

# The draw line is a statement whose value feeds a cookie, the session or a
# response header.
_sink_re := `\b\w*[Ss]ession\w*(?:\(\))?\s*\.\s*(?:setValue|setAttribute|put)\s*\(|\bnew\s+(?:javax\.servlet\.http\.|jakarta\.servlet\.http\.)?Cookie\s*\(|\.setAttribute\s*\(|\.addCookie\s*\(|\.(?:set|add)Header\s*\(`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:private|public|protected|static|final|volatile|transient)\s+)*(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*=(?:[^=]|$)`, line, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)*[\w.<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w., ]+)?\{?\s*$`

_gen_method_re := `(?i)(?:token|nonce|secret|password|passwd|salt|otp|pin|session\w*id|sessid|apikey|api_key|csrf|xsrf|resetcode|reset_code|verificationcode|key)`

_security_use(_, _, code) if regex.match(_sensitive_re, code)

# Stored straight into a cookie, the session or a header.
_security_use(_, _, code) if regex.match(_sink_re, code)

_security_use(lines, i, code) if {
	vs := _produced(code)
	count(vs) > 0
	end := min([count(lines) - 1, i + 6])
	end >= i + 1
	re0 := concat("", [`\b(?:`, concat("|", vs), `)\b`])
	# one assignment away: String key = encode(bytes);
	vs1 := vs | {w |
		some k in numbers.range(i + 1, end)
		regex.match(re0, lines[k])
		w := _assigned(lines[k])
	}
	re1 := concat("", [`\b(?:`, concat("|", vs1), `)\b`])
	some k in numbers.range(i + 1, end)
	regex.match(re1, _blank(lines[k]))
	not helpers.is_comment_line(lines[k])
	regex.match(concat("|", [_sensitive_re, _sink_re]), _with_lhs(lines, k))
}

# Line k with the line above it when that line is the left-hand side of a
# continued assignment (`Supplier<String> SESSION_ID =` / `() -> ++id + ...`).
_with_lhs(lines, k) := concat(" ", [_blank(lines[k - 1]), _blank(lines[k])]) if {
	k > 0
	regex.match(`=\s*$`, lines[k - 1])
} else := _blank(lines[k])

_security_use(lines, i, code) if {
	_returned(lines, i, code)
	decls := [j |
		some j in numbers.range(max([0, i - 15]), i - 1)
		regex.match(_method_re, lines[j])
	]
	count(decls) > 0
	m := regex.find_all_string_submatch_n(_method_re, lines[max(decls)], 1)
	regex.match(_gen_method_re, m[0][1])
}

# The variable that holds the drawn value: the one assigned, or the buffer
# nextBytes(buf) fills.
_produced(code) := {v | v := _assigned(code)} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\.\s*nextBytes\s*\(\s*(\w+)\s*\)`, code, 1)
}

# The drawn value is what the method returns.
_returned(_, _, code) if regex.match(`^\s*return\b`, code)

_returned(lines, i, code) if {
	some v in _produced(code)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	regex.match(concat("", [`^\s*return\b.*\b`, v, `\b`]), lines[k])
}

_draw(code, _) if regex.match(_inline_draw_re, code)

_draw(code, vres) if {
	vres[0] != ""
	regex.match(vres[0], code)
}

# A weak generator handed to a helper in a return statement:
# `return scramble(random, hash)` in createPasswordReset().
_draw(code, vres) if {
	vres[1] != ""
	regex.match(`^\s*return\b`, code)
	regex.match(vres[1], code)
}

_vres(vars) := [_var_draw_re(vars), concat("", [`[(,]\s*(?:`, concat("|", vars), `)\s*[,)]`])] if count(vars) > 0

_vres(vars) := ["", ""] if count(vars) == 0

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`Random|Math\.random`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	vres := _vres(_weak_vars(lines))
	some i, line in lines
	regex.match(`Random|random|\.next|\.ints|\.longs|\.doubles`, line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	_draw(code, vres)
	_security_use(lines, i, code)
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
