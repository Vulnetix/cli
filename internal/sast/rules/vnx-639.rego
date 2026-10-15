# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_639

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-639",
	"name": "Authorization Bypass Through User-Controlled Key",
	"description": "A record is fetched, changed or deleted by an identifier the client supplies, with nothing nearby tying the record to the caller (insecure direct object reference). Reported: an ORM or repository lookup by id (Express/Mongoose/Sequelize/Prisma findById/findByPk/findOne/findUnique/findFirst/findByIdAndUpdate/findByIdAndDelete/destroy/deleteOne/updateOne/update/delete/upsert and DAO get...By...Id methods; Django objects.get/filter/exclude and get_object_or_404, Flask-SQLAlchemy query.get/get_or_404/filter_by, get_by_id; Spring Data/DAO findById/getById/getOne/getReferenceById/deleteById/findOne/find/findBy...Id and EntityManager.find; Rails Model.find/find_by/find_by_id/destroy/delete) whose arguments carry an id-like key from the request (req.params/query/body, request.GET/POST/args/form/values/json/data/query_params/COOKIES, Rails params, request.getParameter) inline, through a variable assigned or destructured from it in the 12 lines above, or through a Spring @PathVariable/@RequestParam parameter, when no owner or authorization check appears in the call or within 10 lines before and 6 after (owner fields, request.user/req.user/current_user, principal/Authentication, @PreAuthorize/@Secured, authorize!/can?/policy_scope, has_perm/check_object_permissions, Forbidden/PermissionDenied/403). Also reported regardless of nearby checks: an owner-scoping field (UserId, userId, user_id, ownerId, accountId) in a JavaScript lookup filled straight from req.body/params/query, because the key that should come from the session is client-controlled. Not reported: lookups scoped through the current user (current_user.orders.find), lookups by non-identifier fields such as email, keys from function parameters with no request origin, test code, comments and string literals. Authorization enforced in middleware, a policy class or a later function is not visible line by line and still produces a finding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-639/",
	"languages": ["java", "node", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [639],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["idor", "authorization", "cwe-639"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
}

_source := {
	"js": `\breq\.(?:params|query|body)\b`,
	"py": `\brequest\.(?:GET|POST|args|form|values|json|get_json|data|query_params|COOKIES|cookies)\b`,
	"rb": `\bparams\s*(?:\[|\.(?:fetch|require|permit))`,
	"java": `\brequest\.getParameter\s*\(`,
}

# The lookup call; group 1 is the rest of the line (its arguments).
_sink := {
	"js": `(?:\b[A-Z]\w*|\b\w*(?:Model|model|Dao|DAO|Repository|Repo|repo|Collection|collection|Store|store)|\bdb\.\w+|\bprisma\.\w+)\.(?:findById|findByPk|findOne|findUnique|findFirst|findOneAndUpdate|findOneAndDelete|findOneAndRemove|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|deleteOne|updateOne|destroy|getById|get\w*By\w*Id\w*|update|delete|upsert)\s*\((.*)$`,
	"py": `(?:\.objects\.(?:get|filter|exclude)|\bget_object_or_404|\.query\.(?:get|get_or_404|filter_by)|\.get_by_id)\s*\((.*)$`,
	"rb": `(?:^|[^\w.:])[A-Z]\w*\.(?:find_by_id|find_by|find|destroy|delete)!?(?:\s*\(|\s+)(.*)$`,
	"java": `(?:\b\w*(?:Repository|Repo|Dao|DAO|repository|repo|dao|Mapper|mapper)\.(?:findById|getById|getOne|getReferenceById|deleteById|findOne|find|findBy\w*Id|selectById|load)|\b(?:em|entityManager)\.find)\s*\((.*)$`,
}

_gate := {
	"js": `req\.(?:params|query|body)`,
	"py": `request\.`,
	"rb": `params`,
	"java": `@PathVariable|@RequestParam|getParameter`,
}

_idish := `\b(?:id|pk|uuid|ID|Id)\b|[a-z0-9](?:Id|ID)\b|_id\b|_pk\b`

_guard := `\bowner\w*|\bOwner\w*|current_?user|currentUser|request\.user\b|req\.user\b|req\.session\.user|session\[:user_id\]|getPrincipal|\bprincipal\b|\bAuthentication\b|@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|has_perm|has_object_permission|check_object_permissions|\bauthorize!?(?:\s|\(|$)|\bcan\?|\bcannot\?|policy_scope|Forbidden|PermissionDenied|AccessDenied|\b403\b|HttpStatus\.FORBIDDEN`

_blank(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# ── Names bound from the request ─────────────────────────────────────────

_bound(lang, lines, i) := helpers.tainted_names(lines, i, 12, _source[lang]) | _destructured(lang, lines, i) | _annotated(lang, lines, i)

# const { id, userId } = req.params, on one line or spread over several.
_destructured("js", lines, i) := {v |
	some j in numbers.range(max([0, i - 12]), i - 1)
	regex.match(`\}\s*=\s*req\.(?:params|query|body)\b`, lines[j])
	opens := [k | some k in numbers.range(max([0, j - 6]), j); regex.match(`(?:const|let|var)\s*\{`, lines[k])]
	count(opens) > 0
	some m in numbers.range(max(opens), j)
	seg := regex.replace(regex.replace(lines[m], `^.*?(?:const|let|var)\s*\{`, ""), `\}\s*=.*$`, "")
	some w in regex.find_all_string_submatch_n(`([A-Za-z_$][\w$]*)\s*(?:[,}]|$)`, seg, -1)
	v := w[1]
}

_destructured(lang, _, _) := set() if lang != "js"

# Spring handler parameters bound from the path or the query string.
_annotated("java", lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(`@(?:PathVariable|RequestParam)\b(?:\([^)]*\))?\s+(?:final\s+)?[\w<>.]+\s+(\w+)`, lines[j], -1)
	v := m[1]
}

_annotated(lang, _, _) := set() if lang != "java"

# ── The finding ──────────────────────────────────────────────────────────

_args(lang, code) := a if {
	m := regex.find_all_string_submatch_n(_sink[lang], code, 1)
	count(m) > 0
	a := m[0][1]
}

# What says the request value is a record key: the request expression with
# its accessor (req.params.id, params[:user_id]), the field it fills
# (pk=request.GET[...]), or the request-bound variable's own name or field.
_evidence(lang, _, _, raw) := {e |
	some m in regex.find_all_string_submatch_n(concat("", [_source[lang], `[^,)}]{0,40}`]), raw, -1)
	e := m[0]
} | {e |
	some m in regex.find_all_string_submatch_n(concat("", [`(\w+)\s*[:=]\s*(?:\w+\()?`, _source[lang]]), raw, -1)
	e := m[1]
}

_evidence_bound(lang, lines, i, raw) := {e |
	some v in _bound(lang, lines, i)
	regex.match(concat("", [`(^|[^\w$.])`, v, `\b`]), raw)
	some e in {v} | {f |
		some m in regex.find_all_string_submatch_n(concat("", [`(\w+)\s*[:=]\s*`, v, `\b`]), raw, -1)
		f := m[1]
	}
}

# Session ids, tokens and captcha ids are looked up by design.
_key_evidence(lang, lines, i, raw) if {
	some e in _evidence(lang, lines, i, raw) | _evidence_bound(lang, lines, i, raw)
	regex.match(_idish, e)
	not regex.match(`(?i)session|token|captcha|csrf|nonce`, e)
}

_idor(lang, lines, i, line) if {
	code := _blank(line)
	_args(lang, code)
	raw := _args(lang, line)
	regex.match(_idish, raw)
	_key_evidence(lang, lines, i, raw)
	not regex.match(_guard, helpers.code_window(lines, i, 10, 6))
}

# The owner key itself comes from the client.
_idor("js", _, _, line) if {
	_args("js", _blank(line))
	regex.match(`\b(?:UserId|userId|user_id|ownerId|owner_id|accountId|account_id|OwnerId)\s*:\s*req\.(?:body|params|query)\.`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:find|get|destroy|delete|update|load|select|query|objects)|get_object_or_404`, line)
	not helpers.is_comment_line(line)
	_idor(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Record looked up by a client-supplied id with no ownership or authorization check: any user can read or change another user's record (IDOR). Scope the query to the authenticated user or check the record's owner",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
