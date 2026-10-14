package vulnetix.rules.vnx_crypto_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-008",
	"name": "Timing attack via direct comparison of secrets",
	"description": "A MAC, signature, digest or secret token is checked with an ordinary equality comparison, which stops at the first differing byte, so response time tells an attacker how much of a forged value is right. Reported: ==, !=, === or !== (Python, Node.js, Go, PHP, Ruby, Java) where one operand is named as a secret value (signature, sig, hmac, mac, digest, hexdigest, token, secret, csrf/xsrf, otp, api_key, including camelCase and snake_case forms such as expectedSignature, csrfToken, x-signature, HTTP_X_HUB_SIGNATURE) and the other is a real value; Java a.equals(b), Arrays.equals and Objects.equals with such an operand; Go bytes.Equal with such an operand; and any equality comparison on a line that computes an HMAC (hmac.new, createHmac, hash_hmac, OpenSSL::HMAC, Mac.doFinal, mac.Sum). Use hmac.compare_digest, crypto.timingSafeEqual, hmac.Equal or subtle.ConstantTimeCompare, hash_equals, ActiveSupport::SecurityUtils.secure_compare or MessageDigest.isEqual. Not reported: presence checks against an empty string, null, None, undefined, nil, a boolean or a number, comparisons with an ALL_CAPS constant or a typeof test (lexer token kinds), comparisons of a .length, .type, size or count, names that only contain hash (geometryHash, location.hash), lines that already use a constant-time comparison, the text inside strings and comments, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-008/",
	"languages": ["python", "node", "go", "java", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [208],
	"capec": ["CAPEC-462"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["crypto", "timing-attack", "hmac"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"php": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"ruby": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"go": `//.*$`,
	"java": `//.*$`,
	"php": `(?://|#).*$`,
	"ruby": `#.*$`,
}

# Subscripts by a literal key (headers['x-signature'], $_SERVER['HTTP_X_SIG'],
# params[:signature]) become member accesses so the key names the operand;
# then string literals are blanked and trailing comments dropped.
_code(lang, line) := c if {
	s1 := regex.replace(line, `\[\s*['"]([\w\-]+)['"]\s*\]`, ".$1")
	s2 := regex.replace(s1, `\[\s*:(\w+)\s*\]`, ".$1")
	t := regex.replace(s2, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

_content_tokens := ["ignature", "SIGNATURE", "sig", "Sig", "hmac", "Hmac", "HMAC", "mac", "Mac", "MAC", "igest", "oken", "TOKEN", "ecret", "SECRET", "srf", "SRF", "otp", "OTP", "pi_key", "piKey", "API_KEY", "doFinal"]

_has_any(s, toks) if {
	some t in toks
	contains(s, t)
}

_constant_time := `compare_digest|timingSafeEqual|hash_equals|hmac\.Equal|ConstantTimeCompare|isEqual|secure_compare|safe_str_cmp|constant_time_compare|constantTimeEquals|timing_safe|timingsafe`

_secret_words := {"signature", "sig", "hmac", "mac", "digest", "hexdigest", "token", "secret", "csrf", "xsrf", "otp"}

_not_value_words := {"length", "size", "type", "kind", "count", "len", "name", "id", "status", "state", "mode", "bytes"}

# last member of an operand chain, without a trailing call and a leading $
_last_seg(op) := s if {
	base := regex.replace(trim_right(op, ":"), `\([^()]*\)$`, "")
	m := regex.find_n(`[\w$\-]+$`, base, 1)
	count(m) > 0
	s := trim_left(m[0], "$")
}

_tail_word(seg) := lower(p) if {
	parts := [x | some x in regex.split(`[_\-]+`, seg); x != ""]
	count(parts) > 0
	p := parts[count(parts) - 1]
	regex.match(`^[A-Z0-9]+$`, p)
}

_tail_word(seg) := lower(ws[count(ws) - 1]) if {
	parts := [x | some x in regex.split(`[_\-]+`, seg); x != ""]
	count(parts) > 0
	p := parts[count(parts) - 1]
	not regex.match(`^[A-Z0-9]+$`, p)
	ws := regex.find_n(`[A-Z]?[a-z0-9]+`, p, -1)
	count(ws) > 0
}

_secret_operand(op) if {
	seg := _last_seg(op)
	w := _tail_word(seg)
	w in _secret_words
	not _token_call(op, w)
}

# cpeToken(x), normalizeToken(s): a function named for tokens returns a
# lexical token, not a credential
_token_call(op, "token") if endswith(trim_right(trim_space(op), ":"), ")")

_secret_operand(op) if {
	seg := _last_seg(op)
	regex.match(`(?i)^(?:x_?)?api_?key$`, seg)
}

_real_operand(op) if {
	t := trim_right(trim_space(op), ":")
	t != ""
	not regex.match(`^(?:""|null|None|undefined|nil|true|false|True|False|NaN|nullptr)$`, t)
	not regex.match(`^-?\d`, t)
	not regex.match(`^[A-Z][A-Z0-9_]*$`, t)
	not startswith(t, `""`)
	not _not_value(t)
}

_not_value(t) if {
	seg := _last_seg(t)
	_tail_word(seg) in _not_value_words
}

_pair_hit(a, b) if {
	_secret_operand(a)
	_real_operand(b)
	_real_operand(a)
}

_pair_hit(a, b) if {
	_secret_operand(b)
	_real_operand(a)
	_real_operand(b)
}

_operand := `[\w$.:\-]+(?:\([^()]*\))?`

_hit(_, code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\s*(?:===|!==|==|!=)\s*(""|`, _operand, `)`]), code, -1)
	_pair_hit(m[1], m[2])
}

_hit("java", code) if {
	some m in regex.find_all_string_submatch_n(`([\w$.]+(?:\([^()]*\))?)\.equals(?:IgnoreCase)?\s*\(\s*([^()]*(?:\([^()]*\))?)\s*\)`, code, -1)
	_pair_hit(m[1], m[2])
}

_hit("java", code) if {
	some m in regex.find_all_string_submatch_n(`\b(?:Arrays|Objects)\.equals\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*([^,()]+(?:\([^()]*\))?)\s*\)`, code, -1)
	_pair_hit(m[1], m[2])
}

_hit("go", code) if {
	some m in regex.find_all_string_submatch_n(`\bbytes\.Equal\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*([^,()]+(?:\([^()]*\))?)\s*\)`, code, -1)
	_pair_hit(m[1], m[2])
}

# an HMAC computed and compared on the same line
_hit(_, code) if {
	regex.match(`\bhmac\.(?:new|digest)\s*\(|\bcreateHmac\s*\(|\bhash_hmac\s*\(|\bHMAC\.(?:hexdigest|digest|base64digest)\s*\(|\.doFinal\s*\(|\b\w*mac\w*\.Sum\s*\(`, code)
	regex.match(`(?:===|!==|==|!=|\.equals\s*\()`, code)
	not regex.match(`(?:===|!==|==|!=)\s*(?:""|null|None|undefined|nil|\d)`, code)
}

# The lines holding a comparison are pulled out with one multi-line regex,
# so only files with a reportable comparison are split and walked for line
# numbers; a weak per-file gate would otherwise walk every line of the repo.
_hit_lines(lang, content) := {t |
	some t in regex.find_n(`(?m)^[^\n]*(?:==|!=|equals|Equal\()[^\n]*$`, content, -1)
	count(t) < 1000
	regex.match(`(?i)sig|mac|digest|token|secret|csrf|xsrf|otp|api|dofinal`, t)
	not helpers.is_comment_line(t)
	not regex.match(_constant_time, t)
	not contains(t, "typeof")
	_hit(lang, _code(lang, t))
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, ["==", "!=", "equals(", "Equal("])
	_has_any(content, _content_tokens)
	not helpers.is_test_path(path)
	hits := _hit_lines(lang, content)
	count(hits) > 0
	lines := split(content, "\n")
	some i, line in lines
	hits[line]
	finding := {
		"rule_id": metadata.id,
		"message": "A MAC, signature or secret token is compared with ordinary equality, which leaks through timing how much of a guess matches; use a constant-time comparison (hmac.compare_digest, crypto.timingSafeEqual, hmac.Equal, hash_equals, secure_compare, MessageDigest.isEqual)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
