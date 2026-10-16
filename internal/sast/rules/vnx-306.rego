# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_306

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-306",
	"name": "Missing Authentication for Critical Function",
	"description": "An administrative Python route is registered with no authentication in front of it. A route counts as administrative when a segment of its path is admin, administrator(s), administration, adminpanel/area/console/dashboard/api, backoffice, superuser, sysadmin, staff or manage/management. Reported: Flask/FastAPI/Quart route decorators (@app.route, @bp.get/post/put/patch/delete, @router.api_route, @app.websocket, also with the path on the next line) whose other decorators carry no auth decorator (login_required, *_required, roles_*, a name with auth/login/admin/role/permission/jwt/token/protect/guard), whose route has no FastAPI dependencies= and whose function takes no Security() parameter and no Depends() on an auth-named dependency (Depends(get_db) is not authentication), and whose first 15 body lines never test the user (current_user, g.user, session[...], request.authorization, is_admin/is_staff/is_superuser, abort(401/403), HTTPException(401/403)), in a file with no before_request hook or APIRouter/FastAPI(dependencies=...); and Flask app.add_url_rule(admin path, view_func=f) where f is defined in the file with no such decorator or check. Not reported: routes whose path is not administrative, the pages an administrator uses before logging in (an admin path ending in login, logout, sign-in, forgot-password, reset-password, static, assets, health), Django admin.site.urls (Django protects it), test files and comments. The same defect in JavaScript/TypeScript and Go routes is reported by VNX-425, and Spring/JAX-RS handlers opened with @PermitAll by VNX-935, so one route is one finding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-306/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [306],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["missing-auth", "critical-function", "cwe-306"],
}

# Python only: an administrative route registered in JavaScript, TypeScript or
# Go is reported by VNX-425, and a Spring handler opened with @PermitAll by
# VNX-935, so one route is one finding.

_admin_seg := `(?i)(?:^|/)(?:admin(?:istrators?|istration|panel|area|console|dashboard|api)?|backoffice|superuser|sysadmin|staff|manage|management)(?:[/_.:-]|$)`

_admin_path(p) if {
	regex.match(_admin_seg, p)
	not _public_page(p)
}

# The pages an administrator reaches before logging in are public by design.
_public_page(p) if regex.match(`(?i)/(?:log_?in|log_?out|sign_?in|sign_?out|sign-in|sign-out|forgot[-_]?password|reset[-_]?password|password[-_]?reset|static|assets|favicon\.ico|health|healthz)/?$`, p)

_message := "This administrative route is registered without any authentication check in front of it: anyone who requests the URL reaches the function. Put it behind an auth decorator or dependency that checks the caller is an authenticated administrator"

# ── Flask / Quart / FastAPI decorators ───────────────────────────────────

_py_route_re := `^\s*@\s*[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*(?:rule\s*=\s*|path\s*=\s*)?[rbf]?["']([^"']*)["']`

_py_route_line(l) if regex.match(`^\s*@\s*[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(`, l)

_py_auth_deco := `(?i)^\s*@\s*[\w.]*(?:login|auth|admin|role|permission|staff|superuser|jwt|token|require|protect|guard|restrict|secure)\w*`

_py_auth_body := `(?i)\bcurrent_user\b|\bg\.user\b|\bsession\s*(?:\[|\.get\s*\()|\bin\s+session\b|request\.authorization|\bis_admin\b|\bis_staff\b|\bis_superuser\b|\babort\s*\(\s*40[13]|\bHTTPException\s*\(\s*(?:status_code\s*=\s*)?40[13]|\bUnauthorized\b|\bForbidden\b|check_auth|authenticate|authoriz|verify_(?:jwt|token|password)|\bget_jwt|jwt_required`

# A FastAPI dependency that authenticates: Security(...), or Depends() on a
# dependency whose name says it checks the caller. Depends(get_db) does not.
_py_auth_dep := `\bSecurity\s*\(|\bDepends\s*\(\s*[\w.]*(?i:auth|user|token|admin|security|verify|current|session|api_?key|login|permission|role|require|guard|principal|staff|jwt|oauth|scope)`

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
	regex.match(_py_auth_dep, w)
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
