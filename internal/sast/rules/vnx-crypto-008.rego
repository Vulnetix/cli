package vulnetix.rules.vnx_crypto_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-008",
	"name": "Timing attack via direct comparison of secrets",
	"description": "A MAC, signature, digest or secret token is checked with an ordinary equality comparison, which stops at the first differing byte, so response time tells an attacker how much of a forged value is right. Reported: ==, !=, === or !== (Python, Node.js, Go, PHP, Ruby, Java) where one operand is named as a secret value (signature, sig, hmac, mac, digest, hexdigest, token, secret, csrf/xsrf, otp, api_key, including camelCase and snake_case forms such as expectedSignature, csrfToken, x-signature, HTTP_X_HUB_SIGNATURE) and the other is a real value; Java a.equals(b), Arrays.equals and Objects.equals with such an operand; Go bytes.Equal with such an operand; any equality comparison on a line that computes an HMAC (hmac.new, createHmac, hash_hmac, OpenSSL::HMAC, Mac.doFinal, mac.Sum); a header read by literal name counts as named by its key (headers.get(\"X-Hub-Signature-256\"), r.Header.Get(\"X-Signature\")), and a literal prefix glued to the value ('sha256=' + expected) is looked through; and a hand-written byte loop that returns at the first difference (if (expected[i] != supplied[i]) return false) in code whose file name, or the 40 lines above (function, class, doc comment), names a MAC, HMAC, signature, digest or secret. An equality comparison is reported only in a verification context, because a timing attack needs one operand the caller supplies: an HMAC, hash or signing call on the line or one of the five above; an enclosing function named verify, validate, valid, check or authenticate; an operand read from a request, header, param, body, cookie or argument, or named for what was supplied or what it is checked against (provided, supplied, received, given, incoming, submitted, candidate, user_, client_, request, header, input, got, expected, computed, calculated); an operand assigned from a request on one of the 30 lines above; or an operand that is a parameter of a request handler (@RequestParam, @RequestHeader, @PostMapping, HttpServletRequest, http.ResponseWriter). Use hmac.compare_digest, crypto.timingSafeEqual, hmac.Equal or subtle.ConstantTimeCompare, hash_equals, ActiveSupport::SecurityUtils.secure_compare or MessageDigest.isEqual. Not reported: presence checks against an empty string, null, None, undefined, nil, a boolean or a number, comparisons with an ALL_CAPS constant or a typeof test (lexer token kinds), comparisons of a .length, .type, size or count, names that only contain hash (geometryHash, location.hash), lines that already use a constant-time comparison, an XOR-accumulating loop, an element loop in code that says nothing about secrets, comparisons where neither side is supplied (two documents' digests, a cache checking its own token, change detection on a refreshed token, a credential compared with a published constant), the text inside strings and comments, and test files.",
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
	# optional chaining (a?.b) reads as a member access
	s0 := regex.replace(line, `\?\.([\w$])`, ".$1")
	s1 := regex.replace(s0, `\[\s*['"]([\w\-]+)['"]\s*\]`, ".$1")
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

# the operand pairs of a line's reportable comparisons
_pairs(lang, code) := _eq_pairs(code) | _lang_pairs(lang, code)

_eq_pairs(code) := {[a, b] |
	some m in regex.find_all_string_submatch_n(concat("", [`(`, _operand, `)\s*(?:===|!==|==|!=)\s*((?:""\s*[+.]\s*)?`, _operand, `|"")`]), code, -1)
	a := m[1]
	# "sha256=" + expected: a literal prefix glued to the value
	b := regex.replace(m[2], `^""\s*[+.]\s*`, "")
	_pair_hit(a, b)
}

_lang_pairs("java", code) := {[a, b] |
	some m in array.concat(
		regex.find_all_string_submatch_n(`([\w$.]+(?:\([^()]*\))?)\.equals(?:IgnoreCase)?\s*\(\s*([^()]*(?:\([^()]*\))?)\s*\)`, code, -1),
		regex.find_all_string_submatch_n(`\b(?:Arrays|Objects)\.equals\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*([^,()]+(?:\([^()]*\))?)\s*\)`, code, -1),
	)
	a := m[1]
	b := m[2]
	_pair_hit(a, b)
}

_lang_pairs("go", code) := {[a, b] |
	some m in regex.find_all_string_submatch_n(`\bbytes\.Equal\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*([^,()]+(?:\([^()]*\))?)\s*\)`, code, -1)
	a := m[1]
	b := m[2]
	_pair_hit(a, b)
}

_lang_pairs(lang, _) := set() if not lang in {"java", "go"}

_hit(lang, code) if count(_pairs(lang, code)) > 0

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
	_verification(lang, lines, i, line)
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

# ---------------------------------------------------------------------------
# Verification context. A timing oracle needs one operand the caller supplies
# and the other a value the code holds. Two documents' digests, a cache's own
# token, change detection on a refreshed credential and a comparison with a
# public constant are none of that, so an equality comparison is reported only
# when one of these says it checks a supplied value:
#   - an HMAC, hash or signing call on the line or on one of the five above;
#   - the enclosing function is named for verifying (verify, validate, valid,
#     check, authenticate);
#   - an operand is named for what was supplied or what it is checked against
#     (provided, received, header, user_, expected, computed...) or is read
#     from a request (req, request, params, headers, cookies, body, $_POST);
#   - an operand is assigned from a request on one of the 30 lines above, or
#     is a parameter of a request handler (@RequestParam, @RequestHeader,
#     @PostMapping, HttpServletRequest, http.ResponseWriter).
# ---------------------------------------------------------------------------

_hash_call := `(?i)(?:\b|_)(?:hmac|digest|hexdigest|md5|sha\d*|sha\w*hex|hash|sign|signature|crypt)\w*\s*\(|\.doFinal\s*\(|\.Sum(?:256|512)?\s*\(|\bSum(?:224|256|384|512)\s*\(`

_verification(_, lines, i, _) if {
	some k in numbers.range(max([0, i - 5]), i)
	not helpers.is_comment_line(lines[k])
	regex.match(_hash_call, regex.replace(lines[k], `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`))
}

_verify_name := `(?i)verif|valid|check|authenticat`

_verification(_, lines, i, _) if {
	d := _decl_line(lines, i)
	regex.match(_verify_name, _decl_name(lines[d]))
}

_supplied_name := `(?i)provided|supplied|received|given|incoming|submitted|candidate|request|header|input|expected|computed|calculated|(?:^|[^a-z])(?:user|client)_|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|(?:^|[^\w])(?:req|params|cookies?|body|args|query|form|got)(?:[^\w]|$)`

_supplied_camel := `(?:^|[^\w])(?:user|client|got)[A-Z]`

_supplied_op(op) if regex.match(_supplied_name, op)

_supplied_op(op) if regex.match(_supplied_camel, op)

_verification(lang, _, _, line) if {
	some pair in _pairs(lang, _code(lang, line))
	some op in pair
	_supplied_op(op)
}

_request_src := `(?i)(?:^|[^\w])(?:req|request|params|headers?|cookies?|body|args|query|form)(?:[^\w]|$)|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\br\.(?:FormValue|PostFormValue|Header|URL|Form|PostForm|Body|Cookie)\b|getParameter|getHeader|getCookies|getQueryString|FormValue|\b(?:c|ctx)\.(?:Query|Param|GetHeader|PostForm|FormValue|Request|Cookie)\b`

# an operand assigned from a request on one of the 30 lines above
_verification(lang, lines, i, line) if {
	some pair in _pairs(lang, _code(lang, line))
	some op in pair
	x := _root(op)
	some k in numbers.range(max([0, i - 30]), i - 1)
	t := lines[k]
	contains(t, x)
	regex.match(concat("", [`(?:^|[^\w.$])\$?`, x, `\s*(?:,\s*[\w$]+\s*)*:?=[^=]`]), t)
	regex.match(_request_src, t)
}

_handler_marker := `@(?:Get|Post|Put|Delete|Patch|Request)Mapping|@RequestParam|@RequestHeader|@RequestBody|@PathVariable|@CookieValue|@(?:Form|Header|Query|Cookie)Param|HttpServletRequest|http\.ResponseWriter|\*gin\.Context|echo\.Context|fiber\.Ctx|Request\s+\$request`

# an operand that is a parameter of a request handler
_verification(lang, lines, i, line) if {
	d := _decl_line(lines, i)
	sig := concat(" ", array.slice(lines, d, min([d + 7, i + 1])))
	ann := concat(" ", array.slice(lines, max([0, d - 4]), min([d + 7, i + 1])))
	regex.match(_handler_marker, ann)
	params := _after_paren(sig)
	some pair in _pairs(lang, _code(lang, line))
	some op in pair
	x := _root(op)
	regex.match(concat("", [`(?:^|[^\w$.])\$?`, x, `\b`]), params)
}

# the first identifier of an operand ($token -> token, self.sig -> sig)
_root(op) := r if {
	segs := regex.find_n(`[\w$]+`, op, 2)
	count(segs) > 0
	r := _skip_self(trim_left(segs[0], "$"), segs)
	r != ""
}

_skip_self(r0, segs) := trim_left(segs[1], "$") if {
	r0 in {"self", "this", "cls"}
	count(segs) > 1
}

_skip_self(r0, _) := r0 if not r0 in {"self", "this", "cls"}

_decl_patterns := [
	`^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*[\[(]`,
	`^\s*(?:async\s+)?def\s+(?:self\.)?(\w+[?!]?)`,
	`\bfunction\s*\*?\s*(\w+)\s*\(`,
	`^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\]|]+\s*)?=>|\w+\s*=>)`,
	`^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default|async|override)\s+)+[\w<>\[\],.?\s]*?(\w+)\s*\(`,
	`^\s*[\w<>\[\],.?]+\s+(\w+)\s*\([^;=]*$`,
]

_not_decl_names := {"if", "for", "while", "switch", "catch", "return", "new", "else", "throw", "elif", "unless", "until", "case", "when"}

_decl_name(t) := ns[0] if {
	not regex.match(`^\s*(?:return|new|else|throw|if|for|while|}|\))`, t)
	ns := [m[1] |
		some p in _decl_patterns
		ms := regex.find_all_string_submatch_n(p, t, 1)
		count(ms) > 0
		m := ms[0]
		not m[1] in _not_decl_names
	]
	count(ns) > 0
}

# the nearest function declaration at or above line i, within 80 lines
_decl_line(lines, i) := max(ds) if {
	ds := [k |
		some k in numbers.range(max([0, i - 80]), i)
		_decl_name(lines[k])
	]
	count(ds) > 0
}

_after_paren(sig) := substring(sig, p, -1) if {
	p := indexof(sig, "(")
	p >= 0
}
