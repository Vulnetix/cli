# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_935

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-935",
	"name": "Administrative endpoint declared without a function-level access check",
	"description": "CWE-935 is the OWASP Top Ten 2013 category 'Missing Function Level Access Control'. This rule reports its most concrete code shape: a route whose path names an administrative function (an /admin, /administrator, /superadmin, /sysadmin, /management, /manage, /backoffice or /staff path segment) declared with nothing that restricts who may call it. Reported: Express-style routes (app, router, *Router, routes, api, server receivers with get/post/put/patch/delete/all) whose only argument after the path is the handler (an inline function or arrow function, or a single handler expression), and router.route('/admin/...').get/post/...(handler) chains whose verb takes only the handler, when the handler's first lines check no role or session and the file mounts no auth middleware with .use(); Flask routes (@app.route, @bp.get/post/put/patch/delete) with no login/admin/role/permission/auth decorator before the def and no current_user, session, g.user, role or abort(401/403) check in the first lines of the function, in a file with no before_request hook; and Spring/JAX-RS handlers (Java and Kotlin) mapped to such a path but annotated @PermitAll, @PreAuthorize(\"permitAll()\"), @Secured(\"IS_AUTHENTICATED_ANONYMOUSLY\") or @AnonymousAllowed, which explicitly open the function to everyone. Not reported: routes with any middleware between path and handler, routers that some file mounts on an admin path behind middleware, handlers that check a role, guarded Flask views and blueprints, Spring handlers without an annotation (Spring Security is configured centrally and VNX-931 judges that configuration), non-admin paths, test files, comments and string literals. Authorization performed in another module (a gateway, a global filter) is not visible to this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-935/",
	"languages": ["node", "python", "java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [935],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["access-control", "authorization", "cwe-935"],
}

_admin_path := `(?i)(^|/)(admin|administrator|superadmin|sysadmin|management|manage|backoffice|staff)([/_\-:.]|$)`

_strip_strings(line) := regex.replace(line, "\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*'|`([^`\\\\]|\\\\.)*`", `""`)

# ── Express ───────────────────────────────────────────────────────────────

_js_ext := `\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`

_js_route := "^\\s*(?:app|router|\\w+Router|routes|api|server)\\s*\\.\\s*(?:get|post|put|patch|delete|all)\\s*\\(\\s*(['\"`])([^'\"`]*)['\"`]\\s*(.*)$"

_js_route_open := `^\s*(?:app|router|\w+Router|routes|api|server)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*$`

# Handler is the only argument after the path.
_js_unguarded(rest) if regex.match(`^,\s*(async\s+)?(function\b|\([^)]*\)\s*(:\s*[\w<>]+\s*)?=>|\w+\s*=>)`, rest)

_js_unguarded(rest) if regex.match(`^,\s*[\w.$]+\s*(\([^,()]*(\([^,()]*\))?[^,()]*\))?\s*\)\s*;?\s*$`, rest)

_js_role_check := `(?i)(isAdmin|is_admin|\.role\b|\.roles\b|hasRole|hasPermission|\.can\(|authori[sz]e|req\.user|req\.session|ctx\.state\.user|status\(\s*40[13]\s*\)|sendStatus\(\s*40[13]\s*\)|forbidden|unauthori[sz]ed)`

# Middleware that authorizes every request (global) or the admin paths. Global
# authentication alone (passport, jwt) does not restrict an admin function.
_js_auth_use := `\.use\(\s*[\w.]*(?i:admin|role|permission|acl|rbac|authoriz)|\.use\(\s*['"][^'"]*(?i:admin|manage|staff|backoffice)[^'"]*['"]\s*,`

# Some file mounts an admin path behind middleware: routers are covered.
_admin_mounted if {
	some path, content in input.file_contents
	regex.match(_js_ext, path)
	regex.match(`\.use\(\s*['"][^'"]*(?i:admin|manage|staff|backoffice)[^'"]*['"]\s*,\s*[^,]+,`, content)
}

_js_route_parts(lines, i) := [m[0][2], m[0][3]] if {
	m := regex.find_all_string_submatch_n(_js_route, lines[i], 1)
	count(m) > 0
}

# router.route('/admin/x').delete(handler): the verb's first argument is the handler.
_js_route_chain := "^\\s*(?:app|router|\\w+Router|routes|api|server)\\s*\\.\\s*route\\s*\\(\\s*(['\"`])([^'\"`]*)['\"`]\\s*\\)\\s*\\.\\s*(?:get|post|put|patch|delete|all)\\s*\\(\\s*(.*)$"

_js_route_parts(lines, i) := [m[0][2], concat("", [", ", m[0][3]])] if {
	m := regex.find_all_string_submatch_n(_js_route_chain, lines[i], 1)
	count(m) > 0
}

_js_route_parts(lines, i) := [m[0][2], m[0][3]] if {
	regex.match(_js_route_open, lines[i])
	i + 1 < count(lines)
	m := regex.find_all_string_submatch_n("^\\s*(['\"`])([^'\"`]*)['\"`]\\s*(.*)$", lines[i + 1], 1)
	count(m) > 0
}

_js_findings contains [path, i] if {
	some path, content in input.file_contents
	regex.match(_js_ext, path)
	not helpers.is_test_path(path)
	regex.match(`(?i)['"\x60][^'"\x60]*/(admin|administrator|superadmin|sysadmin|management|manage|backoffice|staff)`, content)
	not regex.match(concat("", ["(?m)", _js_auth_use]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.\s*(get|post|put|patch|delete|all)\s*\(`, line)
	not helpers.is_comment_line(line)
	parts := _js_route_parts(lines, i)
	regex.match(_admin_path, parts[0])
	_js_unguarded(parts[1])
	not _js_router_covered(line)
	not regex.match(_js_role_check, _js_body(lines, i))
}

# The route line and the lines after it, up to 8, stopping at the next route.
_js_body(lines, i) := concat("\n", array.slice(lines, i, _js_body_end(lines, i)))

_js_body_end(lines, i) := e if {
	nexts := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
		regex.match(`^\s*(?:app|router|\w+Router|routes|api|server)\s*\.`, lines[k])
	]
	count(nexts) > 0
	e := nexts[0]
}

_js_body_end(lines, i) := min([count(lines), i + 8]) if {
	not _js_next_route(lines, i)
}

_js_next_route(lines, i) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	regex.match(`^\s*(?:app|router|\w+Router|routes|api|server)\s*\.`, lines[k])
}

_js_router_covered(line) if {
	not regex.match(`^\s*app\s*\.`, line)
	_admin_mounted
}

# ── Flask ─────────────────────────────────────────────────────────────────

_py_route := `^\s*@\w+\.(?:route|get|post|put|patch|delete)\(\s*[rfu]?['"]([^'"]*)['"]`

_py_guard_deco := `(?i)^\s*@[\w.]*(login_required|admin|role|permission|auth|requires?_|jwt_required|staff|superuser|protected|access|login)`

_py_body_check := `(?i)(current_user\.|is_admin|session\[|session\.get\(|g\.user|has_role|\brole\b|abort\(\s*40[13]\s*\)|verify_jwt|get_jwt)`

_def_index(lines, i) := j if {
	js := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
		regex.match(`^\s*(async\s+)?def\s`, lines[k])
	]
	count(js) > 0
	j := js[0]
}

_py_findings contains [path, i] if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*@\w+\.(route|get|post|put|patch|delete)\(`, content)
	not regex.match(`(?m)^\s*@\w+\.before_(app_)?request\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_space(line), "@")
	m := regex.find_all_string_submatch_n(_py_route, line, 1)
	count(m) > 0
	regex.match(_admin_path, m[0][1])
	d := _def_index(lines, i)
	not _py_decorated(lines, i, d)
	body := concat("\n", array.slice(lines, d + 1, min([count(lines), d + 9])))
	not regex.match(_py_body_check, body)
}

_py_decorated(lines, i, d) if {
	i + 1 <= d - 1
	some k in numbers.range(i + 1, d - 1)
	regex.match(_py_guard_deco, lines[k])
}

# ── Spring / JAX-RS ───────────────────────────────────────────────────────

_open_anno := `^\s*@(PermitAll\b|PreAuthorize\(\s*"permitAll\(\)"\s*\)|Secured\(\s*\{?\s*"IS_AUTHENTICATED_ANONYMOUSLY"|AnonymousAllowed\b)`

_mapping := `@(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|Path)\s*\((.*)\)`

_jvm_findings contains [path, i] if {
	some path, content in input.file_contents
	regex.match(`\.(java|kt)$`, path)
	not helpers.is_test_path(path)
	regex.match(`PermitAll|permitAll\(\)|IS_AUTHENTICATED_ANONYMOUSLY|AnonymousAllowed`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_open_anno, line)
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 3]))
	_same_annotation_block(lines, k, i)
	m := regex.find_all_string_submatch_n(_mapping, lines[k], 1)
	count(m) > 0
	some lit in regex.find_all_string_submatch_n(`"([^"]*)"`, m[0][1], -1)
	regex.match(_admin_path, lit[1])
}

# Every line between the mapping and the annotation is itself an annotation.
_same_annotation_block(lines, k, i) if {
	k != i
	lo := min([k, i])
	hi := max([k, i])
	not _non_annotation_between(lines, lo, hi)
}

_non_annotation_between(lines, lo, hi) if {
	lo + 1 <= hi - 1
	some x in numbers.range(lo + 1, hi - 1)
	not regex.match(`^\s*@`, lines[x])
}

_message :="Administrative endpoint is reachable without a function-level access check: any caller can invoke it. Add an authorization middleware, decorator or role annotation (and check the role on the server)"

findings contains finding if {
	some [path, i] in (_js_findings | _py_findings) | _jvm_findings
	lines := split(input.file_contents[path], "\n")
	not regex.match(`^\s*$`, _strip_strings(lines[i]))
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
