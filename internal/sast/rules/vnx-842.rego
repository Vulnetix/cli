# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_842

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-842",
	"name": "Placement of User into Incorrect Group",
	"description": "A user is put into a privileged group or role without anyone with the authority to grant it deciding so. Reported in Python and JavaScript/TypeScript: (1) the group, role or privilege flag given to a user is taken from the request (Django user.groups.add(Group.objects.get(name=request.POST[...])), user.role = request.json[...], User(role=...)/create_user(is_staff=...) or a Mongoose/Sequelize/Prisma create({ role: req.body.role }) and its shorthand, user.isAdmin = req.body.isAdmin, doc[\"role\"] = request.form[\"role\"], user.roles.push(...)/user.roles.append(...), user_datastore.add_role_to_user(user, request.form[...]), addUserToGroup(..., req.query.group), a Cognito AdminAddUserToGroup GroupName from the body), directly or through a variable assigned from the request within the 20 lines above; (2) a user model whose role/group/access-level column or field defaults to an administrative value (default=\"admin\", default: 'superuser', @Column({ default: 'admin' })) or whose is_admin/is_staff/is_superuser/isAdmin flag defaults to true, so every new account starts privileged; (3) a register/sign-up/create-account/onboarding function that puts the new user into an administrative group or role (groups.add(... 'Administrators'), role = 'admin', is_superuser = True, isAdmin: true). Not reported: a request-supplied role checked against an allow-list or in a condition first (a bare presence check such as if (!role) or if not role: is not validation and is still reported), a role change behind an admin or permission check within the 15 lines above (requireAdmin, @admin_required, @permission_required, has_perm, authorize...), query filters (find/filter/filter_by on role), constant non-privileged roles, management commands and seed scripts that create administrators on purpose, comments and strings. Only roles and groups named in code are understood; a privilege granted through a database lookup is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-842/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [842],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["placement-of-user-into-incorrect-group", "cwe-842", "mass-assignment", "privilege"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

# Whole-file gate: the file names a role/group/privilege field at all.
_gate := `(?i)role|group|is_?admin|is_?staff|superuser|access_?level|user_?type|account_?type`

# Substrings one of which every role/group/flag name contains, for cheap
# file and line gates ahead of the case-insensitive expressions.
_needles := {"role", "Role", "ROLE", "group", "Group", "dmin", "taff", "uperuser", "ccessLevel", "ccess_level", "serType", "ser_type", "ccountType", "ccount_type", "ermissions", "sOwner", "s_owner", "oderator"}

_signup_needles := {"egist", "ign_up", "ignup", "ignUp", "SignUp", "Signup", "reate_account", "reateAccount", "nboard", "nrol", "elf_serv", "elfserv", "elfServ"}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Per-line gate: a role/group/flag name followed by an assignment, a key, a
# shorthand separator, or a group/role call.
_line_gate := `(?i)\b(?:role|roles|groups?|user_?type|account_?type|access_?level|user_?role|is_?admin|is_?staff|is_?superuser|is_?moderator|is_?owner|permissions|GroupName)\b['"]?\]?\s*(?:[:=,}]|$)|\.groups\.|\.roles\.|_role_to_|togroup|_to_group|(?:assign|add|set|grant)role`

# String literals that contain whitespace are prose or embedded code, never a
# role name: blanking them keeps `"... role=request.form['role'] ..."` from
# reading as an assignment while 'admin' and "group" survive.
_code(line) := regex.replace(regex.replace(regex.replace(line, "`[^`]*`", "``"), `("[^"\s]*")|"[^"\n]*"`, "${1}"), `('[^'\s]*')|'[^'\n]*'`, "${1}")

_priv := `(?i:admin|administrators?|superusers?|super_?admins?|root|owners?)`

_role_keys := {
	"py": `role|roles|group|groups|user_type|account_type|access_level|user_role|permissions`,
	"js": `role|roles|group|groups|userType|accountType|accessLevel|userRole|user_role|permissions`,
}

_flag_keys := {
	"py": `is_admin|is_staff|is_superuser|is_moderator|is_owner`,
	"js": `isAdmin|is_admin|isStaff|isSuperuser|isSuperUser|isOwner|isModerator`,
}

_source := {
	"py": `\b(self\.)?request\.(POST|GET|REQUEST|data|json|form|args|values|get_json|query_params|path_params|params|body|query)\b`,
	"js": `\b(req|request)\.(body|query|params|headers|cookies)\b|\bctx\.request\.body\b|\bctx\.(query|params)\b`,
}

# ── (1) Privilege from the request ───────────────────────────────────────

# Value expressions the line hands to a role, group or flag.
_sink_values(c, "py") := {v |
	m := regex.find_all_string_submatch_n(concat("", [`\.(`, _role_keys.py, `|`, _flag_keys.py, `)\s*=\s*([^=].*)$`]), c, 1)
	count(m) > 0
	v := m[0][2]
} | {v |
	m := regex.find_all_string_submatch_n(`\.groups\.(?:add|set)\s*\((.*)\)|\badd_(?:user_)?to_group\s*\((.*)\)|\.roles\.(?:append|add|extend)\s*\((.*)\)|\badd_role_to_user\s*\((.*)\)`, c, 1)
	count(m) > 0
	v := concat(" ", [m[0][1], m[0][2], m[0][3], m[0][4]])
} | {v |
	v := _subscript_value(c, "py")
}

# doc["role"] = ..., user['isAdmin'] = ...
_subscript_value(c, lang) := v if {
	m := regex.find_all_string_submatch_n(concat("", [`\[\s*["'](?:`, _role_keys[lang], `|`, _flag_keys[lang], `)["']\s*\]\s*=\s*([^=].*)$`]), c, 1)
	count(m) > 0
	v := m[0][1]
}

_sink_values(c, "js") := {v |
	m := regex.find_all_string_submatch_n(concat("", [`\.(`, _role_keys.js, `|`, _flag_keys.js, `)\s*=\s*([^=].*)$`]), c, 1)
	count(m) > 0
	v := m[0][2]
} | {v |
	m := regex.find_all_string_submatch_n(`\b(?:addUserToGroup|adminAddUserToGroup|addToGroup|assignRole|addRole|setRole|grantRole|addRoleToUser)\s*\((.*)\)|\.(?:roles|groups)\.(?:push|unshift|add)\s*\((.*)\)`, c, 1)
	count(m) > 0
	v := concat(" ", [m[0][1], m[0][2]])
} | {v |
	v := _subscript_value(c, "js")
}

# Keyword arguments (Python) and object keys (JavaScript) count only inside a
# call that creates or updates a record: User(role=...), create({ role }).
_kw_values(lines, i, c, "py") := {v |
	_creates_py(lines, i)
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:`, _role_keys.py, `|`, _flag_keys.py, `)\s*=\s*([^=,)\s][^,)]*)`]), c, -1)
	v := m[1]
}

_kw_values(lines, i, c, "js") := {v |
	_creates_js(lines, i)
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:`, _role_keys.js, `|`, _flag_keys.js, `|GroupName)\s*:\s*([^,}]+)`]), c, -1)
	v := m[1]
} | {v |
	_creates_js(lines, i)
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[{,])\s*(`, _role_keys.js, `|`, _flag_keys.js, `)\s*(?:[,}]|$)`]), c, -1)
	v := m[1]
}

_create_py := `(?:\b[A-PR-Z]\w*\(|\bcreate_(?:user|superuser)\s*\(|\.create\s*\(|\.update\s*\(|get_or_create\s*\(|update_or_create\s*\()`

_creates_py(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i)
	regex.match(_create_py, lines[j])
}

_create_js := `(?:\.create\w*|\.insert\w*|\.build|\.save|\bnew\s+[A-Z]\w*|\.update\w*|\.upsert|\bregister\w*|\bsign[Uu]p)\s*\(`

_creates_js(lines, i) if {
	some j in numbers.range(max([0, i - 6]), i)
	regex.match(_create_js, lines[j])
}

# Names assigned from the request (first hop, including destructuring) and
# from such a name (second hop) in the 20 lines above.
_hop1(lines, i, lang) := {v | some v in helpers.tainted_names(lines, i, 20, _source[lang])} | {n |
	i > 0
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(_source[lang], lines[j])
	m := regex.find_all_string_submatch_n(`(?:const|let|var)\s*\{([^}]*)\}\s*=`, lines[j], 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	n := trim_space(split(trim_space(part), ":")[count(split(trim_space(part), ":")) - 1])
	regex.match(`^[A-Za-z_]\w*$`, n)
}

_tainted(lines, i, lang) := t1 | t2 if {
	t1 := _hop1(lines, i, lang)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 20]), i - 1)
		not helpers.is_comment_line(lines[j])
		v := helpers.assigned_first(lines[j])
		some t in t1
		t != v
		regex.match(concat("", [`=.*\b`, t, `\b`]), lines[j])
	}
}

_from_request(lines, i, v, lang) if regex.match(_source[lang], v)

_from_request(lines, i, v, lang) if {
	some t in _tainted(lines, i, lang)
	regex.match(concat("", [`\b`, t, `\b`]), v)
}

# The value was tested first (allow-list, condition): it was validated.
_stop := {"req", "request", "body", "query", "params", "POST", "GET", "form", "json", "args", "get", "data", "cookies", "headers", "values", "get_json", "self", "ctx", "String", "str", "int", "Group", "objects", "name", "as", "string"}

_validated(lines, i, v) if {
	i > 0
	some tok in regex.find_all_string_submatch_n(`[A-Za-z_]\w{2,}`, v, -1)
	not _stop[tok[0]]
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(`\b(if|elif|unless|assert|switch|case)\b|\.includes\(|\.indexOf\(|\bnot\s+in\b|\.has\(|\bisIn\b|validate`, l)
	regex.match(concat("", [`\b`, tok[0], `\b`]), l)
	not _presence_only(l, tok[0])
}

# `if (!role) return 400` / `if not role:` checks that a value was sent, not
# which one: it validates nothing.
_presence_only(l, tok) if regex.match(concat("", [`^\s*(?:\}\s*else\s+)?(?:if|elif)\s*\(?\s*(?:!|not\s+)?\s*`, tok, `\s*(?:is\s+None|==\s*None|===?\s*(?:null|undefined))?\s*\)?\s*(?:[:{]|return\b|$)`]), l)

# An admin or permission check guards the code above the line.
_guard := `(?i)(require_?admin|admin_?required|ensure_?admin|is_?admin\s*\(|admin_?only|only_?admins?|permission_required|has_perms?\s*\(|roles?_required|require_?roles?|has_?role\s*\(|check_?role|check_?permission|authorize\s*\(|require_?permission|is_?superuser\s*\(|staff_member_required|user_passes_test|superuser_required|\bif\b.*\b(is_superuser|is_admin|isAdmin|is_staff|isSuperuser)\b)`

_guarded(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(_guard, lines[j])
}

_src_needles := {"py": {"request."}, "js": {"req.", "request.", "ctx."}}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles)
	_has_any(content, _src_needles[lang])
	regex.match(_source[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles)
	regex.match(_line_gate, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	vals := _sink_values(c, lang) | _kw_values(lines, i, c, lang)
	some v in vals
	_from_request(lines, i, v, lang)
	not _validated(lines, i, v)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The user's role, group or privilege flag is taken from the request, so a caller can place themselves into any group, including administrators. Assign the role on the server (a fixed default for self-service sign-up) and let only an authorised administrator change it, against an allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (2) Privileged default on the user model ─────────────────────────────

_default_res := {
	"py": [
		concat("", [`\b(?:`, _role_keys.py, `)\s*=\s*(?:models\.\w+Field|Column|db\.Column|sa\.Column|mapped_column|fields\.\w+)\s*\([^#]*\bdefault\s*=\s*["']`, _priv, `["']`]),
		concat("", [`\b(?:`, _flag_keys.py, `)\s*=\s*(?:models\.BooleanField|Column|db\.Column|sa\.Column|mapped_column|fields\.Bool\w*)\s*\([^#]*\bdefault\s*=\s*True\b`]),
	],
	"js": [
		concat("", [`\b['"]?(?:`, _role_keys.js, `)['"]?\s*:\s*\{[^}]*\b(?:default|defaultValue)\s*:\s*['"]`, _priv, `['"]`]),
		concat("", [`\b['"]?(?:`, _flag_keys.js, `)['"]?\s*:\s*\{[^}]*\b(?:default|defaultValue)\s*:\s*true\b`]),
	],
}

_priv_default(lines, i, c, lang) if {
	some re in _default_res[lang]
	regex.match(re, c)
}

# A multi-line schema field: `default: 'admin',` under `role: {`.
_priv_default(lines, i, c, "js") if {
	regex.match(concat("", [`^\s*(?:default|defaultValue)\s*:\s*(?:['"]`, _priv, `['"]|true)\s*,?\s*$`]), c)
	i > 0
	heads := [j |
		some j in numbers.range(max([0, i - 6]), i - 1)
		regex.match(`^\s*['"]?\w+['"]?\s*:\s*\{\s*$`, lines[j])
	]
	count(heads) > 0
	h := lines[heads[count(heads) - 1]]
	_head_matches(h, c)
}

_head_matches(h, c) if {
	regex.match(concat("", [`^\s*['"]?(?:`, _role_keys.js, `)['"]?\s*:`]), h)
	not regex.match(`:\s*true\b`, c)
}

_head_matches(h, c) if {
	regex.match(concat("", [`^\s*['"]?(?:`, _flag_keys.js, `)['"]?\s*:`]), h)
	regex.match(`:\s*true\b`, c)
}

# TypeORM: @Column({ default: 'admin' }) above `role: string`.
_priv_default(lines, i, c, "js") if {
	regex.match(concat("", [`@Column\s*\(\s*\{[^}]*\bdefault\s*:\s*(?:['"]`, _priv, `['"]|\w+\.(?i:admin|superuser|owner|root)\b|true\b)`]), c)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(concat("", [`^\s*(?:readonly\s+)?(?:`, _role_keys.js, `|`, _flag_keys.js, `)[!?]?\s*:`]), lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "efault")
	_has_any(content, _needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "efault")
	not helpers.is_comment_line(line)
	c := _code(line)
	_priv_default(lines, i, c, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "The user model's role or privilege flag defaults to an administrative value, so every account created without an explicit role, including self-registered ones, starts in the administrators' group. Default to the least-privileged role and grant administration explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (3) Sign-up that grants administration ───────────────────────────────

_grant_res := {
	"py": [
		concat("", [`\.groups\.(?:add|set)\s*\([^)]*['"]`, _priv]),
		concat("", [`\badd_(?:user_)?to_group\s*\([^)]*['"]`, _priv]),
		concat("", [`\b(?:role|group|user_type|account_type|access_level|user_role)\s*=\s*['"]`, _priv, `['"]`]),
		`\b(?:is_admin|is_staff|is_superuser)\s*=\s*True\b`,
	],
	"js": [
		concat("", [`\b(?:role|group|userType|accountType|accessLevel|userRole|GroupName)\s*[:=]\s*['"]`, _priv, `['"]`]),
		`\b(?:isAdmin|is_admin|isStaff|isSuperuser|isSuperUser)\s*[:=]\s*true\b`,
		concat("", [`\b(?:addUserToGroup|adminAddUserToGroup|addToGroup|assignRole|addRole)\s*\([^)]*['"]`, _priv]),
	],
}

_header := {
	"py": `^\s*(?:async\s+)?def\s+\w+`,
	"js": `\bfunction\s*\*?\s*\w*\s*\(|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\(|function|\w+\s*=>)|^\s*(?:async\s+)?\w+\s*\([^)]*\)\s*\{|\.(?:post|put|all)\s*\(\s*['"]`,
}

_signup := `(?i)regist|sign_?up|create_?account|onboard|enrol|self_?serv`

_in_signup(lines, i, lang) if {
	heads := [j |
		some j in numbers.range(max([0, i - 40]), i)
		regex.match(_header[lang], lines[j])
	]
	count(heads) > 0
	regex.match(_signup, lines[heads[count(heads) - 1]])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _signup_needles)
	regex.match(concat("", [`(?i)`, _priv, `|true`]), content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles)
	regex.match(_line_gate, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	some re in _grant_res[lang]
	regex.match(re, c)
	_in_signup(lines, i, lang)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Registration puts the new account into an administrative group or role, so anyone who can sign up becomes an administrator. Give self-registered users the least-privileged role and grant administration through a separate, authorised action",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
