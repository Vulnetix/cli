# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_212

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-212",
	"name": "Improper Removal of Sensitive Information Before Storage or Transfer",
	"description": "A user or account record is serialised whole, password hash included, to a response or an export, because nothing removes the credential field first. Reported: JavaScript/TypeScript res.json/send(user) (also { user }, { items: users }) where the variable was assigned a few lines above from a user/account/member/customer/admin lookup (User/UserModel/db.Account.findById/findOne/findByPk/findOneBy/find/findAll, prisma.user.findUnique/findFirst/findMany), received as the second parameter of the lookup's callback, or taken from the instance that lookup saved (const saved = await user.update(...)), and res.json(await User.findById(...)) on one line, with no .select(), field-list projection argument (find({}, 'name email')), password: 0, attributes/exclude/omit/select: option, delete user.password or password = undefined in between; Python jsonify/JsonResponse/Response/json.dumps of vars(user) or user.__dict__ (current_user, request.user, g.user, any *user/*account name), directly or through a variable assigned from it a few lines above, unless the password is mentioned (popped, deleted or filtered) in between; Django REST Framework ModelSerializers for a User or Account model with fields = '__all__', a fields list naming 'password' or an exclude list that does not, unless the password is declared write_only (extra_kwargs or a write_only field); django.core.serializers.serialize() of User.objects without fields=; model_to_dict(user) or model_to_dict(request.user) without fields= or exclude=; Laravel Eloquent models that extend Authenticatable (or hold 'password' in $fillable) without a $hidden list naming password, $visible, #[Hidden] or makeHidden; Go struct fields holding a password hash (PasswordHash, HashedPassword, PassHash, PasswordDigest; Salt only on a user/account/credential struct) with a JSON tag other than \"-\", and a Password field with a JSON tag on a persisted model (gorm/db/bson/pg/bun tag on the same line). Not reported: DRF serializers for Member or Customer models (usually not the auth model), models related to a user rather than the user model (Profile, UserProfile, UserSettings, AccountActivity), records returned through a projection, a DTO or a toPublic/toJSON method, request structs that only decode a password, schemas whose field sets select: false in the same file, and test code. A field removed by a model transform in another file is not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-212/",
	"languages": ["go", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [212],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["data-handling", "serialization", "password", "cwe-212"],
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

_msg := "A user record is serialised with its password field: the hash (or the password) reaches the response or export. Exclude the field (projection, $hidden, write_only, json:\"-\") or serialise a DTO"

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_file(path) if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_js_lookup := `(?i)(\b(\w+\.)*\w*(user|account|member|customer|admin)s?(model|entity|repo|repository)?\.(findOne|findById|findByPk|findOneBy|findAll|find)\s*\(|\bprisma\.(user|account|member|customer|admin)\.(findUnique|findFirst|findMany)\s*\()`

_js_removed := `\.find\w*\s*\([^,()]*(\([^()]*\))?[^,()]*,\s*['"\x60]|password\w*['"]?\s*:\s*(0|false)\b|\.select\s*\(|\battributes\s*:|\bexclude\b|\bomit\b|\bselect\s*:|\bprojection\b|\bwithout\w*\s*\(|password\s*=\s*(undefined|null|void)|delete\s+[\w.]+\.password\b|\b(toPublic\w*|sanitize\w*|serialize\w*|toDTO|toDto)\s*\(`

_js_sink := `\b(res|resp|response|reply)\s*(\.\s*(status|code)\s*\([^)]*\)\s*)?\.\s*(send|json|jsonp)\s*\(`

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "find")
	not helpers.is_test_path(path)
	not regex.match(`\bselect\s*:\s*false\b`, content)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "find")
	not helpers.is_comment_line(al)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*(?:await\s+)?(.*)$`, al, 1)
	count(m) > 0
	regex.match(_js_lookup, m[0][2])
	v := m[0][1]
	i := _js_sent(lines, a, v)[_]
	f := _finding(path, i, lines[i], _msg)
}

# res.json(await User.findById(id)): the lookup is the response.
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "await")
	not helpers.is_test_path(path)
	not regex.match(`\bselect\s*:\s*false\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "await")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [_js_sink, `\s*await\s+(.*)$`]), line, 1)
	count(m) > 0
	rest := m[0][count(m[0]) - 1]
	regex.match(concat("", [`^`, _js_lookup]), rest)
	not regex.match(_js_removed, rest)
	f := _finding(path, i, line, _msg)
}

# const user = await User.findByPk(id); const updated = await user.update({...});
# res.json(updated): the saved instance is the same record.
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "find")
	regex.match(`\.(update|save|reload)\s*\(`, content)
	not helpers.is_test_path(path)
	not regex.match(`\bselect\s*:\s*false\b`, content)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "find")
	not helpers.is_comment_line(al)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*(?:await\s+)?(.*)$`, al, 1)
	count(m) > 0
	regex.match(_js_lookup, m[0][2])
	not regex.match(_js_removed, al)
	v := m[0][1]
	some k in numbers.range(a + 1, min([count(lines) - 1, a + 3]))
	mm := regex.find_all_string_submatch_n(concat("", [`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?`, v, `\s*\??\.\s*(update|save|reload)\s*\(`]), lines[k], 1)
	count(mm) > 0
	i := _js_sent(lines, k, mm[0][1])[_]
	f := _finding(path, i, lines[i], _msg)
}

# User.findById(id, (err, user) => { ... res.json(user) }): the record is the
# callback's second parameter.
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "find")
	not helpers.is_test_path(path)
	not regex.match(`\bselect\s*:\s*false\b`, content)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "find")
	not helpers.is_comment_line(al)
	regex.match(_js_lookup, al)
	m := regex.find_all_string_submatch_n(`(?:\(\s*|function\s*\w*\s*\(\s*)[A-Za-z_$][\w$]*\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*(?:=>|\{)`, al, 1)
	count(m) > 0
	v := m[0][1]
	i := _js_sent(lines, a, v)[_]
	f := _finding(path, i, lines[i], _msg)
}

# Lines within six below a that send v whole, with nothing removed between.
_js_sent(lines, a, v) := {i |
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(_js_sink, line)
	regex.match(concat("", [`\.\s*(send|json|jsonp)\s*\(\s*(`, v, `\s*\)|\{\s*([^}]*?,\s*)?(\w+\s*:\s*)?`, v, `\s*[,}]|\[\s*`, v, `\s*\])`]), line)
	window := concat("\n", [l | some k in numbers.range(a, i); l := lines[k]; not helpers.is_comment_line(l)])
	not regex.match(_js_removed, window)
}

# ── Python: Django REST Framework and django.core.serializers ────────────

# The user model itself (User, CustomUser, auth.User, Account), not a model
# related to it (UserProfile, AccountActivity), which has no password field.
_py_user_model := `^\s*model\s*=\s*(get_user_model\s*\(\s*\)|[\w.]*(User|Account))\s*$`

# Flask/Django: the user object's whole attribute dict as the response.
_py_whole := `(?i)\bvars\(\s*((current_user|request\.user|self\.request\.user|g\.user)|\w*(user|account))\s*\)|\b((current_user|request\.user|g\.user)|\w*(user|account))\.__dict__\b`

_py_sink := `\b(jsonify|JsonResponse|make_response|Response|json\.dumps)\s*\(`

# Any handling of the password field in the window (pop, del, a key filter)
# counts as removing it.
_py_pops_password(s) if regex.match(`(?i)password`, s)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_has_any_py(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any_py(line)
	not helpers.is_comment_line(line)
	regex.match(_py_whole, line)
	regex.match(_py_sink, line)
	not _py_pops_password(line)
	f := _finding(path, i, line, _msg)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_has_any_py(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	_has_any_py(al)
	not helpers.is_comment_line(al)
	regex.match(`^\s*[A-Za-z_]\w*\s*=[^=]`, al)
	regex.match(_py_whole, al)
	not regex.match(_py_sink, al)
	v := helpers.assigned_first(al)
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(concat("", [_py_sink, `\s*`, v, `\s*[,)]`]), line)
	not _py_pops_password(concat("\n", array.slice(lines, a, i + 1)))
	f := _finding(path, i, line, _msg)
}

_has_any_py(s) if contains(s, "__dict__")

_has_any_py(s) if contains(s, "vars(")

_py_write_only(content) if regex.match(`(?s)["']password["']\s*:\s*\{[^}]*["']write_only["']\s*:\s*True`, content)

_py_write_only(content) if regex.match(`\bpassword\s*=\s*serializers\.\w+\([^)]*write_only\s*=\s*True`, content)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "ModelSerializer")
	regex.match(`(?m)^\s*(fields|exclude)\s*=`, content)
	not helpers.is_test_path(path)
	not _py_write_only(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(fields|exclude)\s*=`, line)
	_py_fields_expose(line)
	some j in numbers.range(max([0, i - 4]), i - 1)
	regex.match(_py_user_model, lines[j])
	f := _finding(path, i, line, _msg)
}

_py_fields_expose(line) if regex.match(`^\s*fields\s*=\s*(["']__all__["']|[\[(][^\])]*["']password["'])`, line)

# exclude = (...) that leaves the password in.
_py_fields_expose(line) if {
	regex.match(`^\s*exclude\s*=\s*[\[(]`, line)
	not contains(line, "password")
}

# model_to_dict(user) without fields= or exclude= copies every column,
# password included.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "model_to_dict(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "model_to_dict(")
	not helpers.is_comment_line(line)
	regex.match(`(?i)\bmodel_to_dict\(\s*(request\.user|self\.request\.user|[\w.]*\b(user|account|member|customer|admin))\s*\)`, line)
	f := _finding(path, i, line, _msg)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "serialize(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "serialize(")
	not helpers.is_comment_line(line)
	regex.match(`\bserializers?\.serialize\s*\(\s*["'](json|xml|yaml|python|jsonl)["']\s*,\s*(get_user_model\s*\(\s*\)|[\w.]*(User|Account))\.objects\b`, line)
	not regex.match(`\bfields\s*=`, line)
	f := _finding(path, i, line, _msg)
}

# ── PHP: Laravel Eloquent user models ────────────────────────────────────

_php_hides(content) if regex.match(`(?s)\$hidden\s*=\s*\[[^\]]*["']password["']`, content)

_php_hides(content) if regex.match(`\$visible\s*=|#\[Hidden\b|makeHidden\s*\(|function\s+toArray\s*\(`, content)

_php_user_model(content) if contains(content, "extends Authenticatable")

_php_user_model(content) if regex.match(`(?s)\$fillable\s*=\s*\[[^\]]*["']password["']`, content)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "password")
	regex.match(`\bextends\s+(Authenticatable|Model|User)\b`, content)
	not helpers.is_test_path(path)
	_php_user_model(content)
	not _php_hides(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(final\s+)?class\s+\w+\s+extends\s+(Authenticatable|Model|User)\b`, line)
	f := _finding(path, i, line, _msg)
}

# ── Go: model structs whose JSON form carries the password ───────────────

_go_tag_json(line) if {
	m := regex.find_all_string_submatch_n(`json:"([^"]*)"`, line, 1)
	count(m) > 0
	not startswith(m[0][1], "-")
}

_go_hash_field := `^\s*(?i:password_?(hash|hashed|digest|salt|crypt)|hashed_?password|pass_?hash|pw_?hash|pwd_?hash|password_?bcrypt|salt)\s+[\w\[\]*.]+\s+\x60`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)(pass|pw|salt)\w*\s+[\w\[\]*.]+\s+\x60`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "json:")
	regex.match(`(?i)^\s*(pass|pw|hash|salt)`, line)
	_go_field_exposed(lines, i, line)
	f := _finding(path, i, line, _msg)
}

_go_field_exposed(_, _, line) if {
	regex.match(_go_hash_field, line)
	not regex.match(`(?i)^\s*salt\s`, line)
	_go_tag_json(line)
}

# A bare Salt is public by design in key-derivation parameters; it counts only
# on a user or account struct.
_go_field_exposed(lines, i, line) if {
	regex.match(`(?i)^\s*salt\s`, line)
	_go_tag_json(line)
	decls := [k |
		some k in numbers.range(max([0, i - 30]), i - 1)
		regex.match(`^\s*type\s+\w+\s+struct\b`, lines[k])
	]
	count(decls) > 0
	regex.match(`(?i)^\s*type\s+\w*(user|account|member|customer|admin|credential)\w*\s+struct\b`, lines[max(decls)])
}

_go_field_exposed(_, _, line) if {
	regex.match(`^\s*(Password|Passwd|Pwd)\s+[\w\[\]*.]+\s+\x60`, line)
	regex.match(`\b(gorm|db|bson|pg|bun|sql|dynamodbav|firestore):"`, line)
	_go_tag_json(line)
}
