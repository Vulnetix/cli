# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_287

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-287",
	"name": "Improper Authentication: check that always succeeds",
	"description": "An authentication routine accepts every caller because its body does nothing but succeed. Reported in Python, Java and JavaScript/TypeScript production code: a function or method named for an authentication decision (authenticate*, check/verify/validate password, credentials, login, token, JWT, API key, signature, OTP/MFA, session; is_valid_password, isTokenValid, isPasswordValid and the like; Java PasswordEncoder.matches in a file that implements PasswordEncoder) whose first statement is an unconditional return True/true/Boolean.TRUE (also with a trailing TODO comment, with the parameter list spread over several lines, a one-line Java or JS body, an annotated Java method, a JS object-literal method or property arrow, and an arrow function whose body is true), and a NestJS-style canActivate() inside a class named for authentication (JwtAuthGuard, AuthGuard...) whose first statement is return true; an Express-style authentication middleware (requireAuth, ensureAuthenticated, isLoggedIn, checkJwt, authenticate... taking next) whose first statement is next(); and a Python login_required/requires_auth decorator that returns the wrapped view unchanged. Not reported: any routine whose first statement is a check (if, a lookup, a hash comparison), a returned verification call (return bcrypt.compare(...)), model flags such as is_authenticated/is_active properties, authorisation predicates (has_permission, supports, isEnabled), ordinary middleware that is not named for authentication, test, fixture, __mocks__ and Storybook code, a canActivate() in a guard not named for authentication, and comments or string literals. Whether a stub is reachable in a deployed configuration is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-287/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["authentication", "auth-bypass", "cwe-287"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

# Names of routines whose answer is the authentication decision.
_auth_name_re := `(?i)^(authenticate\w*|(check|verify|validate|is_?valid|confirm)_?(user_?)?(password|passwd|pwd|pass|credentials?|creds|login|token|jwt|api_?key|signature|otp|totp|mfa|2fa|session|auth\w*)|is_?(user_?)?(password|passwd|pwd|credentials?|creds|login|token|jwt|api_?key|signature|otp|totp|mfa|2fa|session)_?(valid|correct|ok|matches?)|password_?(matches|valid|ok)|matches_?password)$`

# Names of middleware that guards a route by authentication.
_mw_name_re := `(?i)^((require|ensure|check|verify|is)_?(auth\w*|logged_?in|login|user|session|token|jwt)|authenticate\w*|auth_?(middleware|guard|check|required)?|logged_?in)$`

# Names of Python decorators that guard a view by authentication.
_deco_name_re := `(?i)^(login_?required|requires?_?(auth\w*|login)|auth\w*_?required|authenticated)$`

_header_re := {
	"py": `^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)[^:]*:\s*(?:#.*)?$`,
	"java": `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|default)\s+)*(?:boolean|Boolean)\s+(\w+)\s*\(([^)]*)\)`,
	"js": `^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)\)`,
}

_js_method_re := `^\s*(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*\(([^)]*)\)\s*(?::\s*[^{=]+)?\{\s*(?://.*)?$`

# Object-literal method: `verifyPassword: function (plain, hash) {`.
_js_prop_fn_re := `^\s*(\w+)\s*:\s*(?:async\s+)?function\s*\*?\s*\w*\s*\(([^)]*)\)\s*\{\s*(?://.*)?$`

_js_arrow_re := `^\s*(?:(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=|(\w+)\s*:)\s*(?:async\s*)?(?:\(([^)]*)\)|(\w+))\s*(?::\s*[^=]+)?=>\s*(.*)$`

# A declaration whose parameters run over several lines (black, prettier):
# the opening line and the line that closes the parameter list.
_ml_open_re := {
	"py": `^\s*(?:async\s+)?def\s+(\w+)\s*\(\s*$`,
	"java": `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|default)\s+)*(?:boolean|Boolean)\s+(\w+)\s*\(\s*$`,
	"js": `^\s*(?:export\s+)?(?:default\s+)?(?:(?:public|private|protected|static|async|override)\s+)*(?:function\s*\*?\s*)?(\w+)\s*\(\s*$`,
}

_ml_close_re := {
	"py": `^\s*\)\s*(?:->[^:]*)?:\s*(?:#.*)?$`,
	"java": `^\s*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$`,
	"js": `^\s*\)\s*(?::\s*[^{=]+)?\{\s*(?://.*)?$`,
}

# [name, params, index of the line that ends the declaration]
_decl_at(lang, lines, i) := [d[0], d[1], i] if {
	d := _decl(lang, lines[i])
	not regex.match(`\{[^}]*\S[^}]*\}`, lines[i])
}

_decl_at(lang, lines, i) := [m[0][1], params, e] if {
	m := regex.find_all_string_submatch_n(_ml_open_re[lang], lines[i], 1)
	count(m) > 0
	not m[0][1] in _keywords
	ends := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
		regex.match(_ml_close_re[lang], lines[k])
	]
	count(ends) > 0
	e := ends[0]
	params := concat(" ", array.slice(lines, i + 1, e))
}

_keywords := {"if", "for", "while", "switch", "catch", "function", "return", "constructor", "else"}

# Declarations: name, params, and the index of the line whose statement is
# the body's first (or -1 with an inline body string).
_decl(lang, line) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(_header_re[lang], line, 1)
	count(m) > 0
}

_decl("js", line) := [m[0][1], m[0][2]] if {
	not regex.match(_header_re.js, line)
	m := regex.find_all_string_submatch_n(_js_method_re, line, 1)
	count(m) > 0
	not m[0][1] in _keywords
}

_decl("js", line) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(_js_prop_fn_re, line, 1)
	count(m) > 0
}

_first_stmt(lines, i) := j if {
	j0 := helpers.next_code_index(lines, i, 4)
	j := _skip_open_brace(lines, j0)
}

_skip_open_brace(lines, j) := k if {
	trim_space(lines[j]) == "{"
	k := helpers.next_code_index(lines, j, 3)
} else := k if {
	regex.match(`^\s*[rbuRBU]?("""|''').*("""|''')\s*$`, lines[j])
	k := helpers.next_code_index(lines, j, 3)
} else := j

# A trailing comment (`return True  # TODO`) does not change the statement.
_return_true := `^\s*return\s+(true|True|Boolean\.TRUE)\s*;?\s*(#.*|//.*|/\*.*)?$`

_next_call := `^\s*(return\s+)?next\(\)\s*;?\s*(//.*|/\*.*)?$`

_auth_named(lang, name, ctx) if {
	regex.match(_auth_name_re, name)
}

_auth_named("java", "matches", ctx) if contains(ctx.content, "PasswordEncoder")

# A NestJS/Angular guard's canActivate answers for the guard's class, so the
# class name says whether it is an authentication guard.
_auth_named("js", "canActivate", ctx) if {
	lines := ctx.lines
	i := ctx.i
	classes := [n |
		some k in numbers.range(max([0, i - 80]), i - 1)
		contains(lines[k], "class ")
		m := regex.find_all_string_submatch_n(`\bclass\s+(\w+)`, lines[k], 1)
		count(m) > 0
		n := m[0][1]
	]
	count(classes) > 0
	regex.match(`(?i)(auth|jwt|login|session|token|apikey)\w*guard$`, classes[count(classes) - 1])
}

_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)__mocks__/|\.stories\.[jt]sx?$`, path)

_has_next(params) if regex.match(`(^|[\s,(])next\b`, params)

# The body's first statement is the stub.
_stub(lang, name, params, stmt, ctx) if {
	regex.match(_return_true, stmt)
	_auth_named(lang, name, ctx)
}

_stub(lang, name, params, stmt, _) if {
	lang != "py"
	_has_next(params)
	regex.match(_mw_name_re, name)
	regex.match(_next_call, stmt)
}

_stub("py", name, params, stmt, _) if {
	regex.match(_deco_name_re, name)
	p := trim_space(split(params, ",")[0])
	p != ""
	regex.match(concat("", [`^\s*return\s+`, p, `\s*$`]), stmt)
}

# Lower-case substrings every reported routine name contains: a cheap gate on
# the file and on each line before any regular expression runs.
_needles := {"auth", "pass", "pwd", "cred", "token", "jwt", "apikey", "api_key", "login", "logged", "signature", "otp", "mfa", "2fa", "session", "matches", "canactivate"}

_named(s) if {
	l := lower(s)
	some n in _needles
	contains(l, n)
}

# Multi-line body: the statement after the declaration.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not _test_path(path)
	_named(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	_named(line)
	not helpers.is_comment_line(line)
	d := _decl_at(lang, lines, i)
	j := _first_stmt(lines, d[2])
	_stub(lang, d[0], d[1], lines[j], {"content": content, "lines": lines, "i": i})
	finding := _finding(path, j, lines[j])
}

# One-line body: `boolean matches(...) { return true; }`.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang != "py"
	not _test_path(path)
	_named(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "}")
	regex.match(`true|TRUE|next\(\)`, line)
	_named(line)
	not helpers.is_comment_line(line)
	d := _decl(lang, regex.replace(line, `\{.*$`, "{"))
	m := regex.find_all_string_submatch_n(`\{\s*([^{}]*?)\s*\}\s*,?\s*$`, line, 1)
	count(m) > 0
	_stub(lang, d[0], d[1], m[0][1], {"content": content, "lines": lines, "i": i})
	finding := _finding(path, i, line)
}

# Arrow function: `const checkAuth = (req, res, next) => next();`.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	not _test_path(path)
	_named(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=>")
	_named(line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_js_arrow_re, line, 1)
	count(m) > 0
	name := concat("", [m[0][1], m[0][2]])
	params := concat("", [m[0][3], m[0][4]])
	body := trim_space(m[0][5])
	_arrow_stub(name, params, body)
	finding := _finding(path, i, line)
}

_arrow_stub(name, _, body) if {
	regex.match(_auth_name_re, name)
	regex.match(`^true\s*[;,]?$`, body)
}

_arrow_stub(name, params, body) if {
	regex.match(_mw_name_re, name)
	_has_next(params)
	regex.match(`^next\(\)\s*[;,]?$`, body)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "This authentication check always succeeds: its first statement accepts the caller without verifying anything, so any request or password is authenticated. Implement the real verification (credential lookup and constant-time hash comparison, token signature check) or remove the stub",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
