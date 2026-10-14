package vulnetix.rules.vnx_node_019

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-019",
	"name": "Hardcoded JWT or session secret",
	"description": "A string literal is the key that signs or verifies JWTs, session cookies or HMACs, so anyone with the source can forge them and the key cannot be rotated without a release. Reported, in JavaScript and TypeScript: the key argument of jwt.sign()/jwt.verify() (also across line breaks), secret/secretOrKey/secretOrPrivateKey given a literal (or an array of literals) inside express-session, cookie-session, express-jwt, koa-jwt, @fastify/jwt, NestJS JwtModule.register or a passport-jwt Strategy, cookieParser('...'), the key argument of crypto.createHmac(alg, '...'), a const/let/var holding a literal that one of those calls then uses as its key (reported at the assignment), and a config property or variable named for the purpose (jwtSecret, sessionSecret, cookieSecret, tokenSecret, authSecret, signingSecret, JWT_KEY) set to a literal. Not reported: keys from process.env or a config lookup, the literal fallback in process.env.X || '...', an empty string, a TOTP or per-user secret, a literal algorithm name, test files, examples/ directories, comments and calls written inside a string literal. Overlaps VNX-JWT-003 (jwt.sign/encode with a literal key).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-019/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["hardcoded-secret", "jwt", "session", "credentials", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if regex.match(`(^|/)examples?/`, path)

_skip_path(path) if endswith(path, ".min.js")

# Every non-empty string literal becomes 'x' and an empty one ''. A call
# written inside a string disappears with it; a literal argument stays a
# literal.
_norm(line) := regex.replace(
	regex.replace(line, "''|\"\"|``", "\u0001"),
	"'(?:[^'\\\\]|\\\\.)+'|\"(?:[^\"\\\\]|\\\\.)+\"|`[^`$]+`",
	"'x'",
)

_lit := `'x'`

# First argument of a call: an object literal, or an expression without
# top-level commas.
_first := `(?:\{[^{}]*\}|[^,(){}]+(?:\([^()]*\))?)`

_jwt_lit_re := concat("", [`\b(?i:jwt|jsonwebtoken)\s*\.\s*(?:sign|verify)\s*\(\s*`, _first, `\s*,\s*`, _lit, `\s*[,)]`])

_jwt_ident_re := concat("", [`\b(?i:jwt|jsonwebtoken)\s*\.\s*(?:sign|verify)\s*\(\s*`, _first, `\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]`])

_hmac_lit_re := concat("", [`\bcreateHmac\s*\(\s*[^,()]+,\s*`, _lit, `\s*\)`])

_hmac_ident_re := `\bcreateHmac\s*\(\s*[^,()]+,\s*([A-Za-z_$][\w$]*)\s*\)`

_cp_lit_re := concat("", [`\bcookieParser\s*\(\s*(?:`, _lit, `|\[\s*`, _lit, `)`])

_cp_ident_re := `\bcookieParser\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]`

_key_prop := `\b(?:secret|secretOrKey|secretOrPrivateKey)\s*:\s*`

_prop_lit_re := concat("", [_key_prop, `(?:`, _lit, `|\[\s*`, _lit, `)\s*(?:[,}\]]|$)`])

_prop_ident_re := concat("", [_key_prop, `([A-Za-z_$][\w$]*)\s*(?:[,}]|$)`])

# A call that configures session or JWT middleware opens above the property.
_mw_open := `\b(?:session|expressSession|cookieSession|expressJwt|expressjwt|koaJwt|jwt|fastifyJwt|register|registerAsync|Strategy|JwtStrategy)\s*\(`

_in_middleware(lines, i, prop) if {
	prop != "secret"
}

_in_middleware(lines, i, "secret") if {
	regex.match(_mw_open, helpers.code_window(lines, i, 8, 0))
}

_prop_name(line) := n if {
	m := regex.find_all_string_submatch_n(`\b(secret|secretOrKey|secretOrPrivateKey)\s*:`, line, 1)
	n := m[0][1]
}

_named_re := concat("", [
	`(?i)(?:^|[\s{,(])['"]?((?:jwt|session|cookie|token|auth|signing|access[_-]?token|refresh[_-]?token)[_-]?secret(?:[_-]?key)?|jwt[_-]?(?:signing[_-]?)?key)['"]?\s*(?::|=)\s*`,
	_lit, `\s*[,;}]?\s*$`,
])

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}


_files contains [path, lines] if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip_path(path)
	regex.match(`\.(?:sign|verify)\s*\(|createHmac|cookieParser|(?i:secret)|(?i:jwt[_-]?(?:signing[_-]?)?key)`, content)
	lines := split(content, "\n")
}

_sink_line(line) if regex.match(`\.\s*(?:sign|verify)\s*\(|createHmac|cookieParser`, line)

# jwt.sign / jwt.verify with a literal key, on the line or across a break.
findings contains f if {
	some [path, lines] in _files
	some i, line in lines
	regex.match(`\.\s*(?:sign|verify)\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(`\b(?i:jwt|jsonwebtoken)\s*\.\s*(?:sign|verify)\s*\(`, _norm(line))
	regex.match(_jwt_lit_re, _norm(helpers.code_window(lines, i, 0, 3)))
	f := _finding(path, i, line, "jwt.sign()/jwt.verify() uses a hard-coded string as the key; anyone with the source can forge tokens. Load it from process.env or a secrets manager")
}

findings contains f if {
	some [path, lines] in _files
	some i, line in lines
	contains(line, "createHmac")
	not helpers.is_comment_line(line)
	regex.match(_hmac_lit_re, _norm(line))
	f := _finding(path, i, line, "crypto.createHmac() is keyed with a hard-coded string; store the key outside the source")
}

findings contains f if {
	some [path, lines] in _files
	some i, line in lines
	contains(line, "cookieParser")
	not helpers.is_comment_line(line)
	regex.match(_cp_lit_re, _norm(line))
	f := _finding(path, i, line, "cookieParser() signs cookies with a hard-coded secret; anyone with the source can forge signed cookies")
}

findings contains f if {
	some [path, lines] in _files
	some i, line in lines
	regex.match(`\b(?:secret|secretOrKey|secretOrPrivateKey)\s*:`, line)
	not helpers.is_comment_line(line)
	regex.match(_prop_lit_re, _norm(line))
	_in_middleware(lines, i, _prop_name(line))
	f := _finding(path, i, line, "Session/JWT middleware is configured with a hard-coded secret; anyone with the source can forge sessions or tokens. Load it from process.env or a secrets manager")
}

# Identifiers some signing call in the file uses as its key.
_key_idents(lines) := {m[1] |
	some k, l in lines
	_sink_line(l)
	not helpers.is_comment_line(l)
	n := _norm(helpers.code_window(lines, k, 0, 3))
	some re in [_jwt_ident_re, _hmac_ident_re, _cp_ident_re]
	some m in regex.find_all_string_submatch_n(re, n, -1)
} | {m[1] |
	some k, l in lines
	regex.match(`\b(?:secret|secretOrKey|secretOrPrivateKey)\s*:`, l)
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_prop_ident_re, _norm(l), -1)
	_in_middleware(lines, k, _prop_name(l))
}

_const_raw := "^\\s*(?:export\\s+)?(?:const|let|var)\\s+[A-Za-z_$][\\w$]*\\s*(?::\\s*\\w+\\s*)?=\\s*['\"`]"

# A constant holding a literal.
_const_def(line) if {
	regex.match(_const_raw, line)
	regex.match(`^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*(?::\s*\w+\s*)?=\s*'x'\s*;?\s*$`, _norm(line))
}

_const_name(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)`, line, 1)
}

_const_key(line, keys) if {
	_const_def(line)
	_const_name(line) in keys
}

# A constant holding a literal that a signing call then uses as its key.
findings contains f if {
	some [path, lines] in _files
	keys := _key_idents(lines)
	count(keys) > 0
	some i, line in lines
	regex.match(_const_raw, line)
	not helpers.is_comment_line(line)
	_const_key(line, keys)
	f := _finding(path, i, line, "This hard-coded string is used as a JWT/session/HMAC key; anyone with the source can forge what it signs. Load it from process.env or a secrets manager")
}

# A config property or variable named for the purpose holding a literal.
findings contains f if {
	some [path, lines] in _files
	some i, line in lines
	regex.match(`(?i)secret|jwt[_-]?(?:signing[_-]?)?key`, line)
	not helpers.is_comment_line(line)
	regex.match(_named_re, _norm(line))
	not _const_key(line, _key_idents(lines))
	f := _finding(path, i, line, "A JWT/session signing secret is hard-coded; move it to an environment variable or a secrets manager")
}
