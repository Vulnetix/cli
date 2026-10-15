# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_862

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-862",
	"name": "Missing Authorization on a destructive or administrative handler",
	"description": "A Python request handler deletes data or serves an /admin path with no authorization anywhere on its path. Handlers understood: Flask/Quart/FastAPI/Sanic routes (@app.route, @bp.delete, @router.post ...), Django function views in views/api modules (def view(request, ...), @api_view) and Graphene resolvers (def mutate(self, info, ...), def resolve_x(self, info, ...)). Reported on the def line when the body deletes records (ORM .delete(), db.session.delete(obj), delete_one/delete_many, SQL DELETE FROM/DROP TABLE/TRUNCATE) or the route path is under /admin, and none of these is present: an authorization decorator (login_required, roles_required, permission_required, jwt_required, user_passes_test, admin_required, auth.login_required ...), a FastAPI Depends/Security dependency that resolves a user, token, admin or permission (on the handler, or in dependencies=[...] on the APIRouter/FastAPI app in the same file or on an include_router call anywhere), a check in the body (current_user, request.user, g.user, info.context.user, is_authenticated, has_perm, permission/ownership/authorize calls, abort(401/403), PermissionDenied), a before_request/before_app_request hook that aborts or redirects unauthenticated requests anywhere in the project, a Django urls.py wrapping the view in login_required/permission_required, LoginRequiredMiddleware or DRF DEFAULT_PERMISSION_CLASSES, or a Graphene auth middleware. Not reported: read-only handlers outside /admin, functions that are not handlers (model methods, CLI commands, repositories), test files, comments and strings. Authorization enforced by a reverse proxy, or by a decorator whose name does not say what it checks, is invisible to the rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-862/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [862],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["missing-authorization", "cwe-862", "access-control"],
}

# numbers.range counts down when b < a; every window here must be empty instead.
_rng(a, b) := numbers.range(a, b) if a <= b

_rng(a, b) := [] if a > b

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── Handler shapes ───────────────────────────────────────────────────────

_route_deco := `@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(`

_def_re := `^\s*(?:async\s+)?def\s+\w+\s*\(`

_view_path(path) if regex.match(`(^|/)(views?|api|apis)(/[^/]+)?\.py$`, path)

_view_path(path) if regex.match(`(^|/)views/[^/]+\.py$`, path)

# Contiguous decorator block above the def at index i (multi-line decorators
# included): it ends at a blank line, another def/class, or a statement at the
# def's own indent that is not a decorator or a closing bracket.
_deco_text(lines, i) := "" if i == 0

_deco_text(lines, i) := txt if {
	i > 0
	di := _indent(lines[i])
	lo := max([0, i - 12])
	stops := [j |
		some j in _rng(lo, i - 1)
		_deco_stop(lines[j], di)
	]
	s := max(array.concat([lo - 1], stops)) + 1
	txt := concat("\n", [lines[k] | some k in _rng(s, i - 1)])
}

_deco_stop(l, _) if trim_space(l) == ""

_deco_stop(l, _) if regex.match(`^\s*(?:async\s+def|def|class)\b`, l)

_deco_stop(l, di) if {
	_indent(l) <= di
	t := trim_left(l, " \t")
	not startswith(t, "@")
	not startswith(t, ")")
	not startswith(t, "]")
}

# The handler's signature: the def line up to the line closing it.
_signature(lines, i) := txt if {
	hi := min([count(lines) - 1, i + 10])
	ends := [k | some k in _rng(i, hi); regex.match(`\)\s*(?:->[^:]*)?:\s*(?:#.*)?$`, lines[k])]
	e := min(array.concat([hi], ends))
	txt := concat("\n", [lines[k] | some k in _rng(i, e)])
}

# The function body: lines below the def indented deeper than it (80 max).
_body(lines, i) := txt if {
	di := _indent(lines[i])
	hi := min([count(lines) - 1, i + 80])
	ends := [k |
		some k in _rng(i + 1, hi)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= di
	]
	e := min(array.concat([hi + 1], ends)) - 1
	txt := concat("\n", [l | some k in _rng(i + 1, e); l := lines[k]; not helpers.is_comment_line(l)])
}

_kind(path, content, lines, i, deco) := "route" if regex.match(_route_deco, deco)

_kind(path, content, lines, i, deco) := "django" if {
	not regex.match(_route_deco, deco)
	_view_path(path)
	regex.match(`def\s+\w+\s*\(\s*request\b`, lines[i])
}

_kind(path, content, lines, i, deco) := "graphql" if {
	not regex.match(_route_deco, deco)
	contains(content, "graphene")
	regex.match(`def\s+(?:mutate|resolve_\w+)\s*\(\s*(?:self|root|_|cls|parent)\s*,\s*info\b`, lines[i])
}

# ── What makes the handler sensitive ─────────────────────────────────────

# ORM calls are matched with string literals removed (a string that quotes
# `.delete()` deletes nothing); SQL statements live inside strings.
_orm_delete := `\.delete\(\s*(?:synchronize_session[^)]*)?\)|\bsession\.delete\(\s*[A-Za-z_][\w.]*\s*\)|\.(?:delete_one|delete_many|bulk_delete)\s*\(`

_sql_delete := `(?i)["'\s]DELETE\s+FROM\s+\w|["'\s](?:DROP|TRUNCATE)\s+TABLE\s+\w`

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'`, `""`)

_sensitive(deco, body, "route") if regex.match(`(?i)["'][^"'\n]*/admin(?:\b|/)`, deco)

_sensitive(_, body, _) if regex.match(_orm_delete, _strip(body))

_sensitive(_, body, _) if regex.match(_sql_delete, body)

# ── Authorization evidence ───────────────────────────────────────────────

_auth_deco := `(?i)@[\w.]*(?:login|auth|permission|perms|roles?_|_roles?\b|role_required|jwt|token|protected|staff|superuser|user_passes_test|admin_required|admin_only|requires?_admin|access_required|scopes?_required|requires?_scope|requires?_user|signed_in|logged_in)`

_auth_dep := `(?i)\b(?:Depends|Security)\(\s*[\w.]*(?:user|auth|admin|token|permission|login|current|verify|scope|security|jwt|api_?key|principal|identity|role)`

_auth_body := `(?i)\bcurrent_user\b|\brequest\.user\b|\bg\.user\b|\bcontext\.user\b|is_authenticated|\bis_admin\b|\bis_staff\b|\bis_superuser\b|has_perms?\s*\(|has_role|check_?perm|permission|authori[sz]|authenticat|abort\(\s*40[13]\b|\b40[13]\b|PermissionDenied|Forbidden|Unauthori[sz]ed|session\s*\[\s*["'](?:user|uid|admin|logged)|session\.get\(\s*["'](?:user|uid|is_admin|admin|logged)|\bowner|get_jwt_identity|verify_jwt|jwt_required|login_required|check_creds|\bensure_\w+\(|\brequire_\w+\(`

_authorized(_, _, deco, _, _) if regex.match(_auth_deco, deco)

_authorized(_, _, deco, _, _) if regex.match(_auth_dep, deco)

_authorized(_, _, _, sig, _) if regex.match(_auth_dep, sig)

_authorized(_, _, _, _, body) if regex.match(_auth_body, body)

_authorized("route", _, _, _, _) if _project_request_guard

_authorized("route", _, _, _, _) if _include_router_guard

# A FastAPI router or app built with an authorization dependency protects
# every route declared on it, in this file or wherever it is included.
_router_dep := `(?i)dependencies\s*=\s*\[[^\]]*\b(?:Depends|Security)\(\s*[\w.]*(?:user|auth|admin|token|permission|login|current|verify|scope|security|jwt|api_?key|principal|identity|role)`

_file_guard("route", content) if {
	regex.match(`\b(?:APIRouter|FastAPI)\s*\(`, content)
	regex.match(_router_dep, content)
}

_include_router_guard if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "include_router")
	regex.match(concat("", [`(?s)include_router\([^)]*`, _router_dep]), content)
}

_authorized("django", name, _, _, _) if _django_project_guard

_authorized("django", name, _, _, _) if _url_wrapped[name]

_authorized("graphql", _, _, _, _) if _graphql_middleware

# A before_request hook that refuses unauthenticated requests, anywhere.
_project_request_guard if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "before_")
	regex.match(`\.before_(?:app_)?request\b`, content)
	regex.match(`(?i)abort\(\s*40[13]\b|login_required|unauthori[sz]ed|forbidden|is_authenticated|redirect\(\s*url_for\(\s*["'][\w.]*login`, content)
	not helpers.is_test_path(path)
}

_django_project_guard if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`LoginRequiredMiddleware|DEFAULT_PERMISSION_CLASSES`, content)
}

_url_wrapped contains name if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "urlpatterns")
	some m in regex.find_all_string_submatch_n(`(?:login_required|permission_required\([^)]*\)|staff_member_required|user_passes_test\([^)]*\)|superuser_required)\s*\(\s*(?:\w+\.)*(\w+)`, content, -1)
	name := m[1]
}

_graphql_middleware if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?i)class\s+\w*(?:auth|login|permission)\w*middleware`, content)
}

# A def inside a triple-quoted string is text, not a handler.
_in_triple_string(lines, i) if {
	before := concat("\n", array.slice(lines, 0, i))
	n := count(regex.find_all_string_submatch_n(`"""|'''`, before, -1))
	n % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "def ")
	regex.match(`(?m)@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|def\s+\w+\s*\(\s*request\b|def\s+(?:mutate|resolve_\w+)\s*\(\s*\w+\s*,\s*info\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "def ")
	regex.match(_def_re, line)
	deco := _deco_text(lines, i)
	kind := _kind(path, content, lines, i, deco)
	body := _body(lines, i)
	_sensitive(deco, body, kind)
	name := regex.find_all_string_submatch_n(`def\s+(\w+)`, line, 1)[0][1]
	not _authorized(kind, name, deco, _signature(lines, i), body)
	not _file_guard(kind, content)
	not _in_triple_string(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Handler '%s' deletes data or serves an admin path without any authorization check: anyone who can reach the route can perform it. Add an authorization decorator or dependency (login_required, permission_required, a role check) or check the caller's rights in the handler", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
