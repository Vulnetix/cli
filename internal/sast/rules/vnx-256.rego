# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_256

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-256",
	"name": "Plaintext Storage of a Password",
	"description": "A password received in a request is stored as it arrived, with no hashing. Reported when the value is a request field (Flask/Django request.form/args/values/POST/GET/json, Express req.body/query/params, servlet getParameter() or a form/DTO getPassword(), PHP $_POST/$_GET/$_REQUEST or $request->input(), Go FormValue/PostFormValue/PostForm.Get or gin c.PostForm, Rails params[...]) used directly or through a variable assigned from one up to 15 lines above (including JavaScript destructuring of req.body, and a field of such a variable: data[\"password\"], body.password), and it is written to: a password field of an object (user.password = ..., $user->password = ..., u.Password = ...); a setPassword(...) setter; a password key of a model create/insert/build call (Model.create, objects.create, insertOne, new Model({...}), Model(...).save(), and a Python obj = Model(..., password=...) followed by obj.save() within three lines); a password member on its own line inside a multi-line create call or model literal opened up to six lines above (prisma.user.create({ data: { password: ... } }), a Python User(\n password=...), a Go &models.User{ Password: ... }), and SQLAlchemy session.add(User(..., password=...)); or an SQL INSERT/UPDATE whose text names a password column, when a password-named variable or a password request field is bound within the next four lines. Also reported regardless of the source: a password stored on the client, in localStorage/sessionStorage.setItem, a response cookie (res.cookie, set_cookie, setcookie, new Cookie, cookies[:password]) or document.cookie, under a key named password/passwd/pwd/pass. Not reported: a value passed through a hash or key-derivation call (bcrypt, argon2, scrypt, PBKDF2, password_hash, Hash::make, make_password, generate_password_hash, PasswordEncoder.encode, set_password, create_user), or a variable re-assigned from one first; lookups and comparisons (filter, find, WHERE, ==); projects that hash in a model hook or setter (Mongoose pre('save'), Sequelize/TypeORM before-insert hooks, Rails has_secure_password/Devise/before_save, Laravel setPasswordAttribute or a hashed cast, a Python @password.setter); hard-coded password literals (VNX-SEC-014 and VNX-259); comments, strings and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-256/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [256],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-storage", "plaintext", "cwe-256"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if regex.match(`\.(js|jsx|ts|tsx|mjs|cjs)$`, path)

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "ruby" if endswith(path, ".rb")

# A request field, unanchored (for the assignment that taints a variable).
_src("python") := `\brequest\.(?:form|args|values|POST|GET|data|json|get_json)\b`

_src("node") := `\b(?:req|request|ctx\.request)\.(?:body|query|params)\b`

_src("java") := `\.getParameter\s*\(|\b\w*(?:[Ff]orm|[Dd]to|DTO|Request)\.getPassword\(\)`

_src("php") := `\$_(?:POST|GET|REQUEST)\b|\$request->(?:input|get|post)\(`

_src("go") := `\.(?:FormValue|PostFormValue)\(|\.(?:PostForm|Form)\.Get\(|\bc\.(?:PostForm|DefaultPostForm|Query)\(`

_src("ruby") := `\bparams\[`

# The same, as the whole stored expression.
_vsrc("python") := `^request\.(?:form|args|values|POST|GET|data|json|get_json)\b`

_vsrc("node") := `^(?:req|request|ctx\.request)\.(?:body|query|params)\b`

_vsrc("java") := `^\w+\.getParameter\s*\(|^\w*(?:[Ff]orm|[Dd]to|DTO|Request)\.getPassword\(\)`

_vsrc("php") := `^\$_(?:POST|GET|REQUEST)\b|^\$request->(?:input|get|post)\(`

_vsrc("go") := `^\w+\.(?:FormValue|PostFormValue)\(|^\w+\.(?:PostForm|Form)\.Get\(|^c\.(?:PostForm|DefaultPostForm|Query)\(`

_vsrc("ruby") := `^params\[`

_hash_words := `(?i)hash|bcrypt|argon|scrypt|pbkdf|crypt|encode|digest|make_password|set_password|create_user|create_superuser|sha\d|md5|hmac`

# ── Tainted variables ───────────────────────────────────────────────────

_assigned("php", line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_assigned(lang, line) := v if {
	lang != "php"
	v := helpers.assigned_first(line)
}

_tainted(lang, lines, i) := {v |
	i > 0
	some k in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[k]
	not helpers.is_comment_line(prev)
	regex.match(_src(lang), prev)
	not regex.match(_hash_words, prev)
	v := _assigned(lang, prev)
	not _rehashed(lines, k, i, v)
} | _destructured(lang, lines, i)

_destructured("node", lines, i) := {v |
	i > 0
	some k in numbers.range(max([0, i - 15]), i - 1)
	m := regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|request|ctx\.request)\.(?:body|query|params)\b`, lines[k], 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	v := trim_space(split(part, ":")[count(split(part, ":")) - 1])
	v != ""
}

_destructured(lang, _, _) := set() if lang != "node"

# The variable was re-assigned through a hash between taint and sink.
_rehashed(lines, k, i, v) if {
	k + 1 <= i - 1
	some j in numbers.range(k + 1, i - 1)
	regex.match(concat("", [`^\s*\$?`, v, `\s*=[^=]`]), lines[j])
	regex.match(_hash_words, lines[j])
}

# The stored expression is the request value itself, or a tainted variable.
_raw_value(lang, expr, tainted) if {
	e := trim(trim_space(expr), " ;,)")
	not regex.match(_hash_words, e)
	regex.match(_vsrc(lang), e)
}

_raw_value(lang, expr, tainted) if {
	e := trim_left(trim(trim_space(expr), " ;,)"), "$")
	e in tainted
}

# data["password"], body.password, $input['password']: a field of a tainted
# request object.
_raw_value(lang, expr, tainted) if {
	e := trim_left(trim(trim_space(expr), " ;,)"), "$")
	not regex.match(_hash_words, e)
	m := regex.find_all_string_submatch_n(`^(\w+)\s*(?:\[\s*["':]?\w+["']?\s*\]|\.\w+|->\w+)$`, e, 1)
	count(m) > 0
	m[0][1] in tainted
}

# ── Project-level hashing hooks ─────────────────────────────────────────

_hook_re("node") := `\.pre\(\s*['"](?:save|validate)['"]|beforeCreate|beforeSave|beforeUpdate|beforeBulkCreate|@BeforeInsert`

_hook_re("ruby") := `has_secure_password|\bdevise\b|before_save|before_create|BCrypt`

_hook_re("python") := `@password\.setter|def _?set_password|hybrid_property`

_hook_re("php") := `setPasswordAttribute|['"]password['"]\s*=>\s*['"]hashed['"]`

_hook_re("java") := `void\s+setPassword\s*\([^)]*\)\s*\{[^}]*(?:encode|hash|BCrypt)`

_hook_re("go") := `func\s+\([^)]*\)\s+(?:BeforeCreate|BeforeSave)\s*\(`

_hooked contains lang if {
	some p, c in input.file_contents
	lang := _lang(p)
	regex.match(_hook_re(lang), c)
}

# ── Sinks ───────────────────────────────────────────────────────────────

_field_re := `(?:\.|->)(?:password|passwd|Password|user_password|UserPassword|pwd)\s*=\s*([^=].*)$`

# `req.body.password = req.body.password.trim()` normalises the request, it
# stores nothing.
_lhs_is_request(lang, line) if regex.match(concat("", [`^\s*(?:`, _src(lang), `)`]), line)

_setter_re :=`\.setPassword\s*\(\s*(.+?)\s*\)\s*;`

_create_re := `(?:\.(?:create|insert|insert_one|insertOne|insertMany|insert_many|build|new|bulkCreate|findOrCreate|upsert|save)\s*\(|\bnew\s+[A-Z]\w*\s*\(\s*\{|\b[A-Z]\w*\s*\(.*\)\.save\(\)|\.(?:add|add_all|merge)\s*\(\s*[A-Z]\w*\s*\().*`

_create_val_re := `\bpassword\s*[=:]\s*([^,)}]+)`

_store(lang, line, tainted) if {
	m := regex.find_all_string_submatch_n(_field_re, line, 1)
	count(m) > 0
	not regex.match(`\b(?:if|elif|unless|while|return|assert)\b`, line)
	not _lhs_is_request(lang, line)
	_raw_value(lang, m[0][1], tainted)
}

_store(lang, line, tainted) if {
	m := regex.find_all_string_submatch_n(_setter_re, line, 1)
	count(m) > 0
	_raw_value(lang, m[0][1], tainted)
}

_store(lang, line, tainted) if {
	regex.match(_create_re, line)
	not regex.match(`(?i)create_user|create_superuser|authenticate|\.filter\(|\.find|\.where\(|\.get\(|exists\(`, line)
	some m in regex.find_all_string_submatch_n(_create_val_re, line, -1)
	_raw_value(lang, m[1], tainted)
}

_store(lang, line, tainted) if {
	lang == "node"
	regex.match(`(?:\.create|\.insert\w*|\bnew\s+[A-Z]\w*)\s*\(\s*\{[^}]*[{,]\s*password\s*[,}]`, line)
	"password" in tainted
}

_sql_re := `(?i)\b(?:insert\s+into\s+\S+\s*\([^)]*\bpass(?:word|wd)?\b|update\s+\S+\s+set\s+[^;]*\bpass(?:word|wd)?\s*=)`

_sql_store(lang, lines, i, tainted) if {
	end := min([count(lines) - 1, i + 4])
	window := concat("\n", array.slice(lines, i, end + 1))
	some v in tainted
	regex.match(`(?i)pass|pwd|^pw$`, v)
	regex.match(concat("", [`\b`, v, `\b`]), window)
}

# The request field bound into the statement names a password; the e-mail or
# user name bound beside a hashed password is not plaintext storage.
_sql_store(lang, lines, i, _) if {
	end := min([count(lines) - 1, i + 4])
	some k in numbers.range(i, end)
	some m in regex.find_all_string_submatch_n(concat("", [`(?:`, _src(lang), `)\s*[\[(]?\s*["':]?(\w+)`]), lines[k], -1)
	regex.match(`(?i)pass|pwd`, m[1])
	not regex.match(_hash_words, lines[k])
}

# ── Client-side storage ─────────────────────────────────────────────────

_key := `(?i:(?:user_?|login_?|saved_?|my_?|account_?)?(?:password|passwd|pwd|pass))`

_client_re := concat("", [
	`(?:(?:localStorage|sessionStorage)\.setItem|\b(?:res|response|reply|ctx)\.cookie|\.set_cookie|\bsetcookie|\bnew\s+Cookie)\s*\(\s*["'\x60]`, _key, `["'\x60]\s*,\s*[^\s)"'\x60]`,
	`|\bcookies\s*\[\s*(?::|["'])`, _key, `["']?\s*\]\s*=\s*[^=\s]`,
	`|\bdocument\.cookie\s*=\s*["'\x60]`, _key, `=`,
])

_in_string(line, idx) if {
	before := substring(line, 0, idx)
	q := count(regex.find_all_string_submatch_n(`["']`, before, -1))
	q % 2 == 1
}

_message := "Password from the request is stored as plaintext; store only a salted hash from bcrypt/argon2/scrypt/PBKDF2 (or your framework's password hasher)"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)pass`, content)
	regex.match(_src(lang), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass|pwd`, line)
	not helpers.is_comment_line(line)
	_sink_line(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_sink_line(lang, lines, i, line) if {
	not lang in _hooked
	not regex.match(_hash_words, line)
	_store(lang, line, _tainted(lang, lines, i))
}

# A password member on its own line inside a multi-line create call or model
# literal opened a few lines above.
_ml_field("node") := `^\s*password\s*:\s*(.+?)\s*,?\s*$`

_ml_field("python") := `^\s*password\s*=\s*(.+?)\s*,?\s*$`

_ml_field("go") := `^\s*Password\s*:\s*(.+?)\s*,?\s*$`

_ml_opener("node") := `(?:\.(?:create|insert\w*|build|upsert|findOrCreate|bulkCreate|save)\s*\(|\bnew\s+[A-Z]\w*\s*\()`

_ml_opener("python") := `(?:\.(?:create|insert\w*|add|bulk_create)\s*\(|\b(?:User|Account|Customer|Member|Profile|Admin)\w*\s*\(\s*$)`

_ml_opener("go") := `(?:\b(?:models?|entity|entities|db|domain)\.\w+|\b(?:User|Account|Customer|Member|Profile|Admin)\w*)\s*\{\s*$`

# The opener's call or literal was closed, or another call opened, before the
# password line.
_closed_between(lines, k, i) if {
	k + 1 <= i - 1
	some j in numbers.range(k + 1, i - 1)
	regex.match(`^\s*[\}\)]\s*\)|^\s*\}\s*$|\w\s*\(\s*\{?\s*$`, lines[j])
}

_sink_line(lang, lines, i, line) if {
	lang in {"node", "python", "go"}
	not lang in _hooked
	not regex.match(_hash_words, line)
	m := regex.find_all_string_submatch_n(_ml_field(lang), line, 1)
	count(m) > 0
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(_ml_opener(lang), lines[k])
	not regex.match(`(?i)create_user|create_superuser|authenticate|login|verify|\.filter\(|\.find|\.where\(`, lines[k])
	not _closed_between(lines, k, i)
	_raw_value(lang, m[0][1], _tainted(lang, lines, i))
}

# A Python model constructed with a password keyword and saved a few lines
# later: `profile = Account(username=u, password=pw)` then `profile.save()`.
_sink_line(lang, lines, i, line) if {
	lang == "python"
	not lang in _hooked
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*=\s*(?:\w+\.)?[A-Z]\w*\s*\(.*\bpassword\s*=\s*([^,)]+)`, line, 1)
	count(m) > 0
	not regex.match(_hash_words, line)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(concat("", [`^\s*`, m[0][1], `\.save\(`]), lines[k])
	_raw_value(lang, m[0][2], _tainted(lang, lines, i))
}

_sink_line(lang, lines, i, line) if {
	regex.match(_sql_re, line)
	_sql_store(lang, lines, i, _tainted(lang, lines, i))
	not _hashed_near(lines, i)
}

_hashed_near(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 4]))
	regex.match(_hash_words, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)(setItem|cookies?)\s*[\(\[=]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass|pwd`, line)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_client_re, line, -1)
	not _in_string(line, indexof(line, m[0]))
	finding := {
		"rule_id": metadata.id,
		"message": "Password stored on the client (web storage or a cookie) in recoverable form; keep passwords server-side and use a session token instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
