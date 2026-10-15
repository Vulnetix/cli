# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_425

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-425",
	"name": "Direct Request ('Forced Browsing')",
	"description": "An administrative route is registered with no authentication or authorisation in front of it, so anyone who requests its URL directly reaches it. A route counts as administrative when a segment of its path is admin, administrator(s), administration, adminpanel/area/console/dashboard/api, backoffice, superuser, sysadmin, staff or manage/management. Reported: Python Flask/FastAPI/Quart route decorators (@app.route, @bp.get/post/put/patch/delete) whose other decorators carry no auth decorator (login_required, *_required, roles_*, a name with auth/login/admin/role/permission/jwt/token/protect/guard), whose route has no FastAPI dependencies= and whose function has no Depends() parameter and whose first 15 body lines never test the user (current_user, g.user, session[...], request.authorization, is_admin/is_staff/is_superuser, abort(401/403)), in a file with no before_request hook or APIRouter(dependencies=...), and Flask app.add_url_rule(admin path, view_func=f) where f is defined in the file with no such decorator or check; Express/Koa/Fastify-style JavaScript/TypeScript app/router .get/.post/.put/.patch/.delete/.all whose only argument after the path is the handler (no middleware), unless an inline handler tests req.user/req.session/isAuthenticated/roles (Koa ctx.state.user, ctx.throw(401/403)), only redirects (res.redirect('/admin/login')), or the file mounts authentication middleware with .use() globally (passport.authenticate, requireAuth, isAuthenticated, ensureLoggedIn, expressjwt and similar names) or on a prefix of the path with any auth-named middleware, or mounts a path-less guard whose name says so (authorize(...), protect, requireRole, adminOnly, *Guard); router.route('/admin/...').get(h) chains whose verb takes only a handler; Go HandleFunc/Handle and gin/echo/chi GET/POST/... with a bare handler name, when the file has no .Use( middleware and the handler, defined in the same file, does not check authentication in its first 15 lines, and the same routes with an inline func literal handler whose first 15 lines check nothing; and a gin/echo route group created for an admin prefix with no middleware argument (admin := r.Group(\"/admin\")) in a file with no .Use(, whose routes pass no auth-named middleware. Not reported: routes whose path is not administrative, the pages an administrator uses before logging in (an admin path ending in login, logout, sign-in, forgot-password, reset-password, static, assets, health), Django admin.site.urls (Django protects it), routes with middleware or an auth decorator, handlers wrapped in a function call (requireAuth(h)), NestJS controllers (guards are often on the class), Spring endpoints (protected by URL rules elsewhere), test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-425/",
	"languages": ["python", "javascript", "typescript", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [425],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["direct-request", "forced-browsing", "missing-authorization", "cwe-425"],
}

_admin_seg := `(?i)(?:^|/)(?:admin(?:istrators?|istration|panel|area|console|dashboard|api)?|backoffice|superuser|sysadmin|staff|manage|management)(?:[/_.:-]|$)`

_admin_path(p) if {
	regex.match(_admin_seg, p)
	not _public_page(p)
}

# The pages an administrator reaches before logging in are public by design.
_public_page(p) if regex.match(`(?i)/(?:log_?in|log_?out|sign_?in|sign_?out|sign-in|sign-out|forgot[-_]?password|reset[-_]?password|password[-_]?reset|static|assets|favicon\.ico|health|healthz)/?$`, p)

_js_exts := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

_is_js(path) if {
	some ext in _js_exts
	endswith(path, ext)
}

_message := "This administrative route is registered without any authentication or authorisation check in front of it: anyone who requests the URL directly reaches it. Put it behind an auth middleware, decorator or dependency that checks the caller is an authenticated administrator"

# ── Python: Flask / Quart / FastAPI decorators ───────────────────────────

_py_route_re := `^\s*@\s*[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*(?:rule\s*=\s*|path\s*=\s*)?[rbf]?["']([^"']*)["']`

_py_route_line(l) if regex.match(`^\s*@\s*[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(`, l)

_py_auth_deco := `(?i)^\s*@\s*[\w.]*(?:login|auth|admin|role|permission|staff|superuser|jwt|token|require|protect|guard|restrict|secure)\w*`

_py_auth_body := `(?i)\bcurrent_user\b|\bg\.user\b|\bsession\s*(?:\[|\.get\s*\()|\bin\s+session\b|request\.authorization|\bis_admin\b|\bis_staff\b|\bis_superuser\b|\babort\s*\(\s*40[13]|\bHTTPException\s*\(\s*(?:status_code\s*=\s*)?40[13]|\bUnauthorized\b|\bForbidden\b|check_auth|authenticate|authoriz|verify_(?:jwt|token|password)|\bget_jwt|jwt_required`

_py_file_guarded(content) if regex.match(`\bbefore_(?:app_)?request\b|APIRouter\s*\([^)]*dependencies\s*=|FastAPI\s*\([^)]*dependencies\s*=`, content)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?i)@\s*[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*(?:rule\s*=\s*|path\s*=\s*)?[rbf]?["'][^"']*(?:admin|backoffice|superuser|sysadmin|staff|manage)`, content)
	not _py_file_guarded(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	contains(line, "@")
	m := regex.find_all_string_submatch_n(_py_route_re, _deco_text(lines, i, n), 1)
	count(m) > 0
	_admin_path(m[0][1])
	not regex.match(`\bdependencies\s*=`, line)
	d := _def_line(lines, i, n)
	not _py_protected(lines, i, d, n)
	finding := _finding(path, i, line)
}

_deco_text(lines, i, n) := concat(" ", [lines[i], trim_space(lines[i + 1])]) if {
	i + 1 < n
	endswith(trim_right(lines[i], " \t\r"), "(")
} else := lines[i]

# The def that the decorator stack starting at i decorates.
_def_line(lines, i, n) := d if {
	end := min([n - 1, i + 10])
	ds := [k | some k in numbers.range(i + 1, end); regex.match(`^\s*(?:async\s+)?def\s`, lines[k])]
	count(ds) > 0
	d := ds[0]
}

_py_protected(lines, i, d, _) if {
	some k in _deco_lines(lines, i, d)
	not _py_route_line(lines[k])
	regex.match(_py_auth_deco, lines[k])
}

_py_protected(lines, i, d, _) if {
	some k in _deco_lines(lines, i, d)
	regex.match(`\bdependencies\s*=`, lines[k])
}

_py_protected(lines, _, d, n) if {
	w := concat("\n", array.slice(lines, d, min([n, d + 16])))
	regex.match(_py_auth_body, w)
}

_py_protected(lines, _, d, n) if {
	w := concat("\n", array.slice(lines, d, min([n, d + 4])))
	regex.match(`\bDepends\s*\(|\bSecurity\s*\(`, w)
}

# app.add_url_rule("/admin/x", view_func=purge): the view is a plain function
# in this file with no auth decorator and no user check.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "add_url_rule")
	not _py_file_guarded(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	contains(line, "add_url_rule")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\.add_url_rule\s*\(\s*(?:rule\s*=\s*)?[rb]?["']([^"']*)["']\s*,(?:.*\bview_func\s*=\s*|\s*(?:None|[rb]?["'][^"']*["'])\s*,\s*)([A-Za-z_][\w.]*)\s*[,)]`, line, 1)
	count(m) > 0
	_admin_path(m[0][1])
	name := _last(split(m[0][2], "."))
	ds := [k | some k, l in lines; regex.match(concat("", [`^\s*(?:async\s+)?def\s+`, name, `\s*\(`]), l)]
	count(ds) > 0
	d := ds[0]
	not _py_protected(lines, d, d, n)
	finding := _finding(path, i, line)
}

# Decorator lines above (contiguous) and below the route decorator.
_deco_lines(lines, i, d) := {k |
	some k in numbers.range(max([0, i - 6]), d - 1)
	k != i
	_in_stack(lines, k, i)
}

_in_stack(_, k, i) if k > i

_in_stack(lines, k, i) if {
	k < i
	every x in numbers.range(k, i - 1) {
		regex.match(`^\s*@|^\s*[)\]},]|^\s+\S`, lines[x])
	}
}

# ── JavaScript / TypeScript: Express-style routers ───────────────────────

_js_route_re := "\\b[A-Za-z_$][\\w$]*\\.(?:get|post|put|patch|delete|del|all)\\s*\\(\\s*(['\"`])([^'\"`]*)['\"`]\\s*,(.*)$"

_js_auth := `(?i)auth|passport|jwt|login|logged|guard|protect|ensure|require|verify|isadmin|role|permission|session\.user|security\.|acl|restrict`

_js_inline_auth := `(?i)req(?:uest)?\.(?:user|session|isAuthenticated|auth)\b|ctx\.state\.user|ctx\.(?:session|isAuthenticated)\b|ctx\.throw\(\s*40[13]|isAdmin|\brole|authoriz|jwt\.verify|status\(\s*40[13]|sendStatus\(\s*40[13]`

# An inline handler that does nothing but redirect (to the login page, or to
# a canonical URL) exposes nothing.
_js_redirect_only(call) if regex.match(`^\s*(?:async\s+)?(?:\([^()]*\)|[\w$]+)\s*=>\s*\{?\s*(?:return\s+)?[\w$]+\.redirect\s*\([^;]*\)\s*;?\s*\}?\s*\)`, call)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match("(?i)\\.(?:get|post|put|patch|delete|del|all)\\s*\\(\\s*['\"`][^'\"`]*(?:admin|backoffice|superuser|sysadmin|staff|manage)", content)
	not _js_global_auth(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	regex.match(`\.(?:get|post|put|patch|delete|del|all)\s*\(`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_js_route_re, line, 1)
	count(m) > 0
	route := m[0][2]
	_admin_path(route)
	not regex.match(`^\s*(?:it|test|describe|cy|request|supertest|axios|fetch|http|client|api|agent)\.`, line)
	not regex.match(`\b(?:axios|request|supertest|client|agent|http|api|cy|\$|jQuery|fetchMock|nock|mock\w*)\s*\.\s*(?:get|post|put|patch|delete|del|all)\s*\(`, line)
	call := _js_call(lines, i, n, m[0][3])
	_single_handler(call)
	not _js_redirect_only(call)
	not regex.match(_js_inline_auth, concat("\n", array.slice(lines, i, min([n, i + 12]))))
	not _js_prefix_auth(content, route)
	finding := _finding(path, i, line)
}

# The rest of the call, joined across up to three following lines.
_js_call(lines, i, n, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, min([n, i + 4]))))

# Arguments after the path, with nested (), [], {} collapsed.
_collapse(s) := regex.replace(regex.replace(regex.replace(regex.replace(regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `\{[^{}]*\}`, "~"), `\{[^{}]*\}`, "~"), `\([^()]*\)`, "~"), `\([^()]*\)`, "~"), `\([^()]*\)`, "~")

_single_handler(call) if regex.match(`^\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*(?::\s*[\w<>\[\]]+\s*)?=>|[\w$]+\s*=>)`, call)

_single_handler(call) if {
	not regex.match(`^\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*(?::\s*[\w<>\[\]]+\s*)?=>|[\w$]+\s*=>)`, call)
	c := _collapse(call)
	m := regex.find_all_string_submatch_n(`^([^()]*)\)`, c, 1)
	count(m) > 0
	args := [a | some a in split(m[0][1], ","); trim_space(a) != ""]
	count(args) == 1
	not regex.match(_js_auth, regex.replace(args[0], `=>.*$|function.*$`, ""))
}

# A global middleware whose name says it enforces authentication.
_js_global_auth(content) if regex.match(`\.use\s*\(\s*(?:[\w$]+\.)*(?:passport\.authenticate|authenticate\w*|(?:require|ensure|is|check|verify|jwt|must)_?(?:Auth\w*|auth\w*|Authenticated|Authorized|LoggedIn|Login|Admin|Token|Jwt|User|Session)|auth(?:Middleware|enticate|Guard|Required)?|expressjwt|expressJwt|jwt|basicAuth|requiresAuth)\b`, content)

# router.use(authorize("admin")), router.use(protect), app.use(adminOnly):
# a path-less middleware whose own name says it guards access.
_js_global_auth(content) if {
	some m in regex.find_all_string_submatch_n(`\.use\s*\(\s*(?:[\w$]+\.)*([\w$]+)\s*[(,)]`, content, -1)
	regex.match(`^(?i:authori[sz]e|protect|guard|restrict|permit|acl|(?:require|has|check)_?(?:role|permission|admin)s?)\w*$|^(?i:admin|staff|login)_?(?i:only|required|guard)$|[a-z]Guard$`, m[1])
}

# router.route("/admin/settings").get(h).post(h2): each verb takes only the
# handler.
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, ".route(")
	not _js_global_auth(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".route(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n("\\.route\\s*\\(\\s*['\"`]([^'\"`]*)['\"`]\\s*\\)\\s*\\.\\s*(?:get|post|put|patch|delete|all)\\s*\\(\\s*([\\w$.]+)\\s*\\)", line, 1)
	count(m) > 0
	route := m[0][1]
	_admin_path(route)
	not regex.match(_js_auth, m[0][2])
	not _js_prefix_auth(content, route)
	finding := _finding(path, i, line)
}

_js_prefix_auth(content, route) if {
	some m in regex.find_all_string_submatch_n("\\.use\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]\\s*,([^\\n]*)", content, -1)
	startswith(route, m[1])
	regex.match(_js_auth, m[2])
}

# ── Go: net/http, gin, echo, chi ─────────────────────────────────────────

_go_route_re := `\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete)\s*\(\s*"([^"]*)"\s*,\s*([A-Za-z_][\w.]*)\s*\)`

_go_auth := `(?i)auth|session|jwt|token|login|isadmin|is_admin|role|permission|StatusUnauthorized|StatusForbidden|BasicAuth|claims|current_?user`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete)\s*\(\s*"[^"]*(?:admin|backoffice|superuser|sysadmin|staff|manage)`, content)
	not regex.match(`\.Use\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)"[^"]*(?:admin|backoffice|superuser|sysadmin|staff|manage)`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_go_route_re, line, 1)
	count(m) > 0
	_admin_path(m[0][1])
	h := m[0][2]
	not regex.match(_go_auth, h)
	body := _go_body(content, h)
	not regex.match(_go_auth, body)
	finding := _finding(path, i, line)
}

# An inline handler: mux.HandleFunc("/admin/x", func(w http.ResponseWriter, r *http.Request) {
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "func(")
	regex.match(`(?i)\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete)\s*\(\s*"[^"]*(?:admin|backoffice|superuser|sysadmin|staff|manage)`, content)
	not regex.match(`\.Use\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "func(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete)\s*\(\s*"([^"]*)"\s*,\s*func\s*\(`, line, 1)
	count(m) > 0
	_admin_path(m[0][1])
	body := concat("\n", array.slice(lines, i + 1, min([count(lines), i + 16])))
	not regex.match(_go_auth, body)
	finding := _finding(path, i, line)
}

# gin/echo: admin := r.Group("/admin") with no middleware argument, in a file
# with no .Use(, whose routes pass no auth-named middleware.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, ".Group(")
	not regex.match(`\.Use\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".Group(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*:?=\s*[\w.]+\.Group\s*\(\s*"([^"]*)"\s*\)`, line, 1)
	count(m) > 0
	_admin_path(m[0][2])
	g := m[0][1]
	routes := regex.find_n(concat("", [`(?m)\b`, g, `\.(?:GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(.*$`]), content, -1)
	count(routes) > 0
	every r in routes {
		not regex.match(_go_auth, r)
	}
	finding := _finding(path, i, line)
}

# The first 15 lines of the handler's definition in this file.
_go_body(content, h) := body if {
	name := _last(split(h, "."))
	lines := split(content, "\n")
	ds := [k | some k, l in lines; regex.match(concat("", [`^func\s+(?:\([^)]*\)\s*)?`, name, `\s*\(`]), l)]
	count(ds) > 0
	body := concat("\n", array.slice(lines, ds[0], min([count(lines), ds[0] + 16])))
}

_last(parts) := parts[count(parts) - 1]

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
