# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_201

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-201",
	"name": "Insertion of Sensitive Information Into Sent Data",
	"description": "An HTTP response sends a credential or other secret that belongs to a stored record. Reported in JavaScript/TypeScript, Python, Go and Java: (1) a response call (res.json/res.send/res.jsonp, ctx.body =, reply.send, jsonify/JsonResponse/make_response, gin/echo c.JSON, json.NewEncoder(w).Encode, ResponseEntity.ok/.body/.entity) whose arguments, on the line or in an object literal continued over the next lines, read a password, password hash, salt, secret, API key, private key, reset token, OTP/TOTP secret, SSN or card number field (user.password, acct.APIKey, user.getPassword()); (2) a whole user/account record fetched from the database (User.findById, User.findOne, userRepository.findById, User.query...first(), h.db.First(&user)) and sent as is (res.json(user), jsonify(user.__dict__), c.JSON(200, user), ResponseEntity.ok(user), res.json(await User.findById(id)) with the lookup inline, or a Spring @GetMapping handler declared to return User/Account that returns userRepository.findById(...).orElseThrow()) when the lookup projects nothing away, nothing in between removes the password, and the project hides no field from serialisation (Mongoose select: false or a toJSON transform, Jackson @JsonIgnore/WRITE_ONLY, a Go json:\"-\" tag); (3) a Django REST Framework ModelSerializer of the User model with fields = '__all__' and no exclude or write_only password. Not reported: a masked or constant value (\"********\"), a derived value (password.length, password != \"\"), a field whose name only starts with a sensitive word (passwordChangedAt), records of other models, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-201/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [201],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["information-leak", "cwe-201"],
}

_lang(path) := "node" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

# Cheap per-file needles for the response sinks.
_needles := {
	"node": {"res.", "ctx.body", "reply."},
	"py": {"jsonify", "JsonResponse", "make_response"},
	"go": {"JSON(", "Encode("},
	"java": {"ResponseEntity", ".body(", ".entity("},
}

_has_any(s, ns) if {
	some n in ns
	contains(s, n)
}

# A response call (or assignment) by language.
_sink_re := {
	"node": `\bres\s*\.\s*(?:status\s*\([^)]*\)\s*\.\s*)?(?:json|send|jsonp)\s*\(|\bctx\.body\s*=|\breply\s*\.\s*(?:code\s*\([^)]*\)\s*\.\s*)?send\s*\(`,
	"py": `\b(?:jsonify|JsonResponse|make_response)\s*\(`,
	"go": `\.(?:JSON|IndentedJSON|PureJSON|JSONP|SecureJSON)\s*\(|\bjson\.NewEncoder\s*\(\s*\w+\s*\)\s*\.\s*Encode\s*\(`,
	"java": `\bResponseEntity\s*\.\s*(?:ok|accepted)\s*\(|\.\s*body\s*\(|\.\s*entity\s*\(`,
}

# A read of a sensitive field used as a value: followed by a separator or the
# end of the line, never by a call, a further member, or a comparison.
_member_re := `(?i)\.(?:password|passwd|password_?hash|hashed_?password|pass_?hash|salt|secret|client_?secret|secret_?key|api_?key|private_?key|reset_?token|otp_?secret|totp_?secret|mfa_?secret|ssn|card_?number|credit_?card(?:_?number)?|cvv)\b\s*(?:[,})\]]|$)|\.get(?:Password|PasswordHash|Salt|Secret|ClientSecret|SecretKey|ApiKey|PrivateKey|ResetToken|Ssn|CardNumber|Cvv)\s*\(\s*\)\s*[,})\]]`

_open_parens(s) := count(split(s, "(")) - count(split(s, ")"))

# String literals are blanked so a message is not mistaken for code.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_msg_field := "The response sends a credential or secret field of a stored record to the client. Return only the fields the client needs and never a password, hash, secret or key"

# ── (1) a sensitive field in a response ─────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles[lang])
	regex.match(_member_re, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_member_re, _without_derived(line))
	_in_response(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": _msg_field,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_in_response(lines, i, lang) if regex.match(_sink_re[lang], lines[i])

# The field sits in an object literal of a response call opened a few lines up
# and not yet closed.
_in_response(lines, i, lang) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(_sink_re[lang], lines[j])
	not helpers.is_comment_line(lines[j])
	_open_parens(concat("\n", array.slice(lines, j, i))) > 0
}

# ── (2) a whole user record sent as is ──────────────────────────────────

_whole_re := {
	"node": [`\bres\s*\.\s*(?:status\s*\([^)]*\)\s*\.\s*)?(?:json|send)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)`, `\bctx\.body\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$`],
	"py": [`\b(?:jsonify|JsonResponse)\s*\(\s*([A-Za-z_]\w*)\.__dict__\s*[,)]`, `\b(?:jsonify|JsonResponse)\s*\(\s*(?:vars|model_to_dict)\s*\(\s*([A-Za-z_]\w*)\s*\)`],
	"go": [`\.(?:JSON|IndentedJSON|PureJSON)\s*\([^,]+,\s*&?([A-Za-z_]\w*)\s*\)`, `\bjson\.NewEncoder\s*\(\s*\w+\s*\)\s*\.\s*Encode\s*\(\s*&?([A-Za-z_]\w*)\s*\)`],
	"java": [`\bResponseEntity\s*\.\s*ok\s*\(\s*([A-Za-z_]\w*)\s*\)`],
}

# A lookup of a user-like model: User.findById(...), Account.findOne(...),
# userRepository.findById(...), User.query.get(...), User.objects.get(...).
_lookup_re := `(?i)\b(?:user|account|customer|member|employee)s?(?:repository|repo|model|dao)?\s*\.\s*(?:find\w*|objects\s*\.\s*(?:get|filter)|query\b|get_or_404)|\b(?:find|get|fetch|load)(?:user|account|customer|member)s?\w*\s*\(`

# A projection or a serialisation-safe accessor on the lookup statement.
_projection_re := `(?i)\.select\s*\(|attributes|exclude|projection|-password|\.only\s*\(|\.values\s*\(|omit|\.Select\s*\(|without|toPublic|toSafe|sanitiz|lean\s*\(\s*\{`

_assigns(line, v, "go") if {
	regex.match(concat("", [`\.(?:First|Find|Take|Last)\s*\(\s*&`, v, `\b`]), line)
}

_assigns(line, v, _) if helpers.assigned_first(line) == v

_assigns(line, v, "node") if {
	regex.match(concat("", [`^\s*(?:const|let|var)\s+`, v, `\s*(?::[^=]+)?=`]), line)
}

_fetched_whole(lines, i, v, lang) if _fetched_direct(lines, i, v, lang)

# One hop: the record is updated or saved and the returned instance is sent.
_fetched_whole(lines, i, v, lang) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	_assigns(l, v, lang)
	m := regex.find_all_string_submatch_n(`=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\??\.\s*(?:update|save|reload|increment)\s*\(`, l, 1)
	count(m) > 0
	not regex.match(_projection_re, l)
	_fetched_direct(lines, j, m[0][1], lang)
	not _scrubbed_between(lines, j, i)
}

_fetched_direct(lines, i, v, lang) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	_assigns(l, v, lang)
	_is_user_lookup(l, v, lang)
	not regex.match(_projection_re, concat(" ", array.slice(lines, j, min([j + 3, i]))))
	not _scrubbed_between(lines, j, i)
}

_is_user_lookup(l, _, _) if regex.match(_lookup_re, l)

# Go: var user User; db.First(&user, id) — the variable's name says what it holds.
_is_user_lookup(l, v, "go") if {
	regex.match(`(?i)^(?:user|account|customer|member)s?$|^u$`, v)
	regex.match(`\.(?:First|Find|Take|Last)\s*\(\s*&`, l)
}

_scrubbed_between(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	not helpers.is_comment_line(lines[k])
	regex.match(`(?i)password|omit|pick\s*\(|sanitiz|toPublic|toSafe|serializ`, lines[k])
}

# The project hides fields from serialisation somewhere.
_hide_needles := {
	"node": {"select: false", "select:false", "toJSON", "defaultScope", "@Exclude", "toObject: {"},
	"java": {"JsonIgnore", "WRITE_ONLY", "@JsonProperty(access"},
	"go": {"json:\"-\""},
	"py": set(),
}

_project_hides(lang) if {
	some path, content in input.file_contents
	_lang(path) == lang
	_has_any(content, _hide_needles[lang])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _needles[lang])
	regex.match(_lookup_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _needles[lang])
	not helpers.is_comment_line(line)
	some re in _whole_re[lang]
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	v := m[0][1]
	_fetched_whole(lines, i, v, lang)
	not _project_hides(lang)
	finding := {
		"rule_id": metadata.id,
		"message": "A whole user/account record from the database is serialised into the response, password hash and all. Project the fields the client needs (or hide the sensitive ones from serialisation) before sending it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The lookup is the response argument itself: res.json(await User.findById(id)),
# or a Spring handler declared to return the entity returns the repository's.
_inline_whole_re := {
	"node": `\bres\s*\.\s*(?:status\s*\([^)]*\)\s*\.\s*)?(?:json|send)\s*\(\s*(?:await\s+)?(?:User|Account|Customer|Member|Employee)s?\s*\.\s*find\w*\s*\(`,
	"java": `^\s*return\s+\w*(?:Repository|Repo|Dao)\s*\.\s*find\w*\s*\((?:[^()]|\([^()]*\))*\)\s*(?:\.\s*(?:orElseThrow|orElse|get)\s*\((?:[^()]|\([^()]*\))*\))?\s*;\s*$`,
}

_inline_context(_, _, "node") := true

_inline_context(lines, i, "java") if {
	head := concat("\n", array.slice(lines, max([0, i - 4]), i))
	regex.match(`(?m)^\s*public\s+(?:Optional<|ResponseEntity<)?(?:User|Account|Customer|Member|Employee)>?\s+\w+\s*\(`, head)
	regex.match(`@(?:Get|Request|Post|Put|Patch)Mapping\b`, head)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang in {"node", "java"}
	regex.match(concat("", ["(?m)", _inline_whole_re[lang]]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_inline_whole_re[lang], line)
	not helpers.is_comment_line(line)
	not regex.match(_projection_re, line)
	_inline_context(lines, i, lang)
	not _project_hides(lang)
	finding := {
		"rule_id": metadata.id,
		"message": "A whole user/account record from the database is serialised into the response, password hash and all. Project the fields the client needs (or hide the sensitive ones from serialisation) before sending it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── (3) DRF ModelSerializer of User exposing every field ────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "__all__")
	contains(content, "ModelSerializer")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*fields\s*=\s*["']__all__["']`, line)
	window := helpers.code_window(lines, i, 8, 8)
	regex.match(`(?m)\bmodel\s*=\s*(?:\w+\.)*(?:User|get_user_model\(\)|Account|CustomUser)\s*$`, concat("\n", array.slice(lines, max([0, i - 4]), i)))
	regex.match(`ModelSerializer`, helpers.code_window(lines, i, 8, 0))
	not regex.match(`\bexclude\s*=|write_only|extra_kwargs`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "A ModelSerializer of the user model serialises every field ('__all__'), including the password hash. List the fields explicitly or mark password write_only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A value derived from the field, not the field: bool(user.password_hash),
# Boolean(user.password), !!user.password, len(user.password).
_derived_re := `\b(?:bool|Boolean|len|hasattr|isinstance)\s*\(\s*[\w.$]+\s*\)|!!\s*[\w.$]+`

_without_derived(line) := regex.replace(_code(line), _derived_re, "0")
