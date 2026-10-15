package vulnetix.rules.vnx_crypto_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-008",
	"name": "Timing attack via direct comparison of secrets",
	"description": "A MAC, signature, digest or secret token is checked with an ordinary equality comparison, which stops at the first differing byte, so response time tells an attacker how much of a forged value is right. Reported: ==, !=, === or !== (Python, Node.js, Go, PHP, Ruby, Java) where one operand is named as a secret value (signature, sig, hmac, mac, digest, hexdigest, token, secret, csrf/xsrf, otp, api_key, including camelCase and snake_case forms such as expectedSignature, csrfToken, x-signature, HTTP_X_HUB_SIGNATURE) and the other is a real value; Java a.equals(b), Arrays.equals and Objects.equals with such an operand; Go bytes.Equal with such an operand; any equality comparison on a line that computes an HMAC (hmac.new, createHmac, hash_hmac, OpenSSL::HMAC, Mac.doFinal, mac.Sum); a header read by literal name counts as named by its key (headers.get(\"X-Hub-Signature-256\"), r.Header.Get(\"X-Signature\")), and a literal prefix glued to the value ('sha256=' + expected) is looked through; and a hand-written byte loop that returns at the first difference (if (expected[i] != supplied[i]) return false) in code whose file name, or the 40 lines above (function, class, doc comment), names a MAC, HMAC, signature, digest or secret. Use hmac.compare_digest, crypto.timingSafeEqual, hmac.Equal or subtle.ConstantTimeCompare, hash_equals, ActiveSupport::SecurityUtils.secure_compare or MessageDigest.isEqual. Not reported: presence checks against an empty string, null, None, undefined, nil, a boolean or a number, comparisons with an ALL_CAPS constant or a typeof test (lexer token kinds), comparisons of a .length, .type, size or count, names that only contain hash (geometryHash, location.hash), lines that already use a constant-time comparison, an XOR-accumulating loop, an element loop in code that says nothing about secrets, the text inside strings and comments, and test files.",
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
	# a header read by name (headers.get("X-Signature", ""), r.Header.Get(...),
	# req.header('x-signature'), getHeader("X-Sig")) is named by its key too
	s3 := regex.replace(s2, `\.(?:get|Get|fetch|header|getHeader|get_header)\s*\(\s*['"]([\w\-]+)['"]\s*(?:,\s*(?:""|''|None|nil|null))?\s*\)`, ".$1")
	t := regex.replace(s3, _strings[lang], `""`)
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
	parts := _parts(seg)
	count(parts) > 0
	p := parts[count(parts) - 1]
	regex.match(`^[A-Z0-9]+$`, p)
}

# name parts split on _ and -, without a trailing all-digit part
# (X-Hub-Signature-256 ends in Signature)
_parts(seg) := [x | some x in regex.split(`[_\-]+`, seg); x != ""; not regex.match(`^\d+$`, x)]

_tail_word(seg) := lower(ws[count(ws) - 1]) if {
	parts := _parts(seg)
	count(parts) > 0
	p := parts[count(parts) - 1]
	not regex.match(`^[A-Z0-9]+$`, p)
	ws := regex.find_n(`[A-Z]?[a-z0-9]+|[A-Z]+`, p, -1)
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
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\s*(?:===|!==|==|!=)\s*((?:""\s*[+.]\s*)?`, _operand, `|"")`]), code, -1)
	# "sha256=" + expected: a literal prefix glued to the value
	_pair_hit(m[1], regex.replace(m[2], `^""\s*[+.]\s*`, ""))
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

# A comparison written by hand, byte by byte, that returns at the first
# difference: if (expected[i] != supplied[i]) return false; inside a loop, in
# code that says (function, class or doc comment above, or the file name) it
# checks a MAC, signature, digest, tag or token.
_loop_lines(content) := {t |
	some t in regex.find_n(`(?m)^[^\n]*\b\w+\s*\[\s*\w+\s*\]\s*!==?\s*\w+\s*\[\s*\w+\s*\][^\n]*$`, content, -1)
	count(t) < 400
	m := regex.find_all_string_submatch_n(`\b(\w+)\s*\[\s*(\w+)\s*\]\s*!==?\s*(\w+)\s*\[\s*(\w+)\s*\]`, t, 1)
	count(m) > 0
	m[0][2] == m[0][4]
	m[0][1] != m[0][3]
	not helpers.is_comment_line(t)
}

_secret_context := `(?i)hmac|signature|\bmac\b|[a-z]Mac\b|digest|\bsig\b|secret|csrf|auth_?tag`

_early_exit(lines, i) if {
	end := min([count(lines) - 1, i + 2])
	some k in numbers.range(i, end)
	regex.match(`\b(?:return\s+(?:false|False|0|-1|nil|null)\b|break\b)`, lines[k])
}

_in_loop(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*(?:for|while)\b|\.forEach\s*\(|\beach(?:_with_index)?\b`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "!=")
	not helpers.is_test_path(path)
	loops := _loop_lines(content)
	count(loops) > 0
	lines := split(content, "\n")
	some i, line in lines
	loops[line]
	_early_exit(lines, i)
	_in_loop(lines, i)
	ctx := concat("\n", array.slice(lines, max([0, i - 40]), i))
	_ctx_ok(path, ctx)
	finding := {
		"rule_id": metadata.id,
		"message": "A MAC, signature or token is compared byte by byte and the loop returns at the first difference, which leaks through timing how much of a guess matches; use a constant-time comparison (hmac.compare_digest, crypto.timingSafeEqual, hmac.Equal, hash_equals, secure_compare, MessageDigest.isEqual)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_ctx_ok(path, _) if regex.match(_secret_context, path)

_ctx_ok(_, ctx) if regex.match(_secret_context, ctx)

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
