# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_566

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-566",
	"name": "Authorization Bypass Through User-Controlled SQL Primary Key",
	"description": "A SELECT, UPDATE or DELETE whose only WHERE condition is a key column (id, uuid, <name>_id, <name>Id) compared with a value the request supplied, in Java or Python, with no ownership or authorization condition in the query and no ownership check nearby, so any caller can read or change another user's record by changing the key. The key counts as request-supplied when it is read on the statement itself or a few lines above from request.getParameter/getHeader, a @PathVariable/@RequestParam/@PathParam/@QueryParam parameter, Flask request.args/form/values/json/view_args, Django request.GET/POST or a Django view parameter, or a Flask route placeholder, and when it reaches the statement (concatenated, interpolated, passed as a bind argument, or bound with setX(n, key) on the following lines). Not reported: a query that adds AND/OR conditions (owner_id = ?, tenant = ?), a key taken from the session or another server-side value, a constant key, a nearby owner/current_user/request.user/g.user/getUserPrincipal check, a nearby 403/Forbidden/PermissionDenied/AccessDenied response, or @PreAuthorize/@Secured/@RolesAllowed/permission_required, a key already passed to a lookup function a few lines above (get_post(id), which commonly loads the record and checks its owner), SQL in comments or in strings that are not queries. Ownership enforced in another function, a database row-level policy or an ORM call is not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-566/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [566],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["sql-auth-bypass", "idor", "cwe-566"],
}

# A query literal whose WHERE clause starts with a key column compared with a
# placeholder or a concatenated/interpolated value.
_query_re := `["'\x60]\s*(?i:select\b.*?\bfrom|update|delete\s+from)\s+\S+.*?\b(?i:where)\s+(?:[\w"\x60]+\.)?["\x60]?(?:(?i:\w+_)?(?i:u?uid|id)|\w+Id|\w+ID)["\x60]?\s*=\s*(?:\?|%s|%\(\w+\)s|:\w+|\{|@\w+|\$\d|'?["']\s*\+)`

_gate_re := `(?i)\bwhere\s+\S*id\S*\s*=`

# A further condition in the WHERE clause.
_extra_cond_re := `(?i)\b(and|or)\s+["\x60]?[\w.]+["\x60]?\s*(=|<|>|!|in\b|is\b|like\b)`

_guard_re := `(?i)\bowner|current_?user|request\.user\b|getRemoteUser|getUserPrincipal|getAuthentication|@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|has_perm|permission_required|authoriz|\bg\.user\b|\babort\(\s*403|PermissionDenied|\bForbidden|SC_FORBIDDEN|HttpStatus\.FORBIDDEN|AccessDenied|sendError\(\s*403`

_java_src_re := `\.(getParameter|getHeader|getQueryString|getPathInfo)\s*\(`

_py_src_re := `\brequest\.(args|form|values|json|data|view_args|GET|POST|query_params|get_json|match_info)\b`

_inline_src_re := `\.getParameter\s*\(|\brequest\.(args|form|values|json|view_args|GET|POST|query_params)\b`

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

# The statement starting at line i: up to 4 lines, until the parentheses opened
# on line i are closed.
_paren_depth(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_span_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 4])
	closed := [k |
		some k in numbers.range(i, last)
		_paren_depth(concat("\n", array.slice(lines, i, k + 1))) <= 0
	]
	e := min(array.concat([last], closed))
}

_span(lines, i) := concat("\n", array.slice(lines, i, _span_end(lines, i) + 1))

# Statements right after the query that bind or execute it.
_use_re := `\.set[A-Z]\w*\(\s*\d+\s*,|\b(execute|executeQuery|executeUpdate|query|queryForObject|queryForList|queryForMap|update|raw)\s*\(`

_uses(lines, i) := concat("\n", [l |
	some k in numbers.range(_span_end(lines, i) + 1, min([count(lines) - 1, i + 5]))
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_use_re, l)
])

# Request-controlled names visible at line i.
_sources(lines, i, "java") := helpers.tainted_names(lines, i, 12, _java_src_re) | _java_params(lines, i)

_sources(lines, i, "py") := (helpers.tainted_names(lines, i, 12, _py_src_re) | _py_view_params(lines, i)) | _py_route_params(lines, i)

_java_params(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(`@(?:PathVariable|RequestParam|PathParam|QueryParam|RequestHeader)\b(?:\([^)]*\))?\s+(?:final\s+)?[\w.<>]+\s+(\w+)`, lines[j], -1)
	v := m[1]
}

_py_view_params(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i)
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?def\s+\w+\(\s*request\s*,([^)]*)\)`, lines[j], 1)
	count(m) > 0
	some p in split(m[0][1], ",")
	v := trim_space(regex.replace(p, `[:=].*$`, ""))
	regex.match(`^[A-Za-z_]\w*$`, v)
	not v in {"self", "args", "kwargs"}
}

_py_route_params(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i)
	regex.match(`^\s*@\w+(\.\w+)*\.(route|get|post|put|patch|delete)\(`, lines[j])
	some m in regex.find_all_string_submatch_n(`<(?:\w+:)?(\w+)>`, lines[j], -1)
	v := m[1]
}

_reaches(text, names) if {
	some v in names
	regex.match(concat("", [`\b`, v, `\b`]), text)
}

_reaches(text, _) if regex.match(_inline_src_re, text)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	regex.match(_query_re, line)
	st := _stmt_start(lines, i)
	span := _span(lines, st)
	not regex.match(_extra_cond_re, span)
	not _continues_with_condition(lines, i)
	names := _sources(lines, i, lang)
	_reaches(concat("\n", [span, _uses(lines, st)]), names)
	not regex.match(_guard_re, helpers.code_window(lines, i, 15, 8))
	not _prechecked(lines, st, names)
	finding := {
		"rule_id": metadata.id,
		"message": "Record selected only by a key the request supplies: any caller can reach another user's row. Add an ownership condition (AND owner_id = <current user>) or check the row's owner before using it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The key was already handed to a lookup function above the statement
# (post = get_post(id), Invoice inv = loadOwned(invoiceId)): that function
# commonly loads the record and enforces its owner, as Flask's tutorial does.
_conversions := {"int", "str", "long", "float", "parseInt", "parseLong", "valueOf", "UUID", "fromString", "len", "print", "println", "isEmpty", "isBlank", "strip", "trim"}

_prechecked(lines, st, names) if {
	st > 0
	some j in numbers.range(max([0, st - 15]), st - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	not regex.match(`^\s*(?:@|(?:async\s+)?def\s|(?:public|private|protected)\b)`, l)
	some v in names
	contains(l, v)
	some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\(\s*`, v, `\s*[,)]`]), l, -1)
	not m[1] in _conversions
}

# The literal is the first argument of a call opened on the line above.
_stmt_start(lines, i) := i - 1 if {
	i > 0
	endswith(trim_space(lines[i - 1]), "(")
} else := i

# The query literal continues on the next line with another condition.
_continues_with_condition(lines, i) if {
	i + 1 < count(lines)
	regex.match(_extra_cond_re, lines[i + 1])
}
