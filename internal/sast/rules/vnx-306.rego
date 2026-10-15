# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_306

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-306",
	"name": "Missing Authentication for Critical Function",
	"description": "An administrative route is registered with no authentication in front of it. Reported: a Flask route decorator (@app.route, @bp.get/post/...) or FastAPI route (@app.get, @router.post, ...) whose path has an admin segment, when none of its decorators names an auth or permission check (login_required, *_required, roles_accepted, jwt, auth, permission, Depends on an auth/user/token/admin dependency, dependencies=), the first lines of the view do not check the user or session (current_user, is_admin, session, abort(401/403), request.user), and no before_request hook or router-wide dependencies are declared in the project; and an Express/Koa route (app.get/post/put/patch/delete/all, router.*) whose path has an admin segment and whose only argument after the path is the handler, when the project mounts no path or global auth middleware with app.use/router.use (passport, auth, isAdmin, requireLogin, jwt, session checks, verifyToken, protect). Not reported: routes with any middleware argument before the handler, Django admin.site.urls (authenticated by Django), non-admin paths, test files, comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-306/",
	"languages": ["node", "python"],
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

_admin_path := `(?i)^[^?#]*(^|/)admin(\b|[-_/])`

_js_exts := {".js", ".ts", ".mjs", ".cjs"}

_is_js(path) if {
	some e in _js_exts
	endswith(path, e)
}

# ── Python ──────────────────────────────────────────────────────────────

_py_route := `^\s*@\s*[\w.]+\.(route|get|post|put|patch|delete|api_route)\(\s*[rfu]?["']([^"']*)["']`

_py_auth := `(?i)(login_required|_required\b|requires?_\w+|roles?_(accepted|required)|auth|permission|jwt|admin_only|superuser|staff_member|Depends\(\s*[\w.]*(auth|user|token|admin|security|verify|current|session|api_key)|dependencies\s*=|Security\()`

_py_body_check := `(?i)(current_user|is_admin|is_authenticated|is_superuser|is_staff|session\[|session\.get|abort\(\s*40[13]|request\.user|g\.user|check_\w*(auth|admin|permission)|verify_\w+|has_perm)`

# A request hook or router-wide dependency protects every route.
_py_project_guard if {
	some p, c in input.file_contents
	endswith(p, ".py")
	regex.match(`(?m)(\.before_(app_)?request\b|APIRouter\([^)]*dependencies\s*=|FastAPI\([^)]*dependencies\s*=|include_router\([^)]*dependencies\s*=)`, c)
}

# Lines of the decorator stack and signature around the route decorator.
_py_def_index(lines, i) := k if {
	end := min([count(lines) - 1, i + 8])
	ks := [j | some j in numbers.range(i + 1, end); regex.match(`^\s*(async\s+)?def\s`, lines[j])]
	count(ks) > 0
	k := ks[0]
}

# The decorator stack starts after the nearest blank line or statement above.
_py_stack_start(lines, i) := s if {
	lo := max([0, i - 8])
	ss := [j |
		some j in numbers.range(lo, i)
		j < i
		_stack_break(lines[j])
	]
	s := max(array.concat([lo - 1], ss)) + 1
}

_stack_break(l) if trim_space(l) == ""

_stack_break(l) if regex.match(`^\s*(async\s+)?(def|class|return|pass|raise)\b`, l)

_py_finding(lines, i) if {
	k := _py_def_index(lines, i)
	s := _py_stack_start(lines, i)
	sig_end := min([count(lines) - 1, k + 3])
	stack := concat("\n", [lines[j] | some j in numbers.range(s, sig_end)])
	not regex.match(_py_auth, stack)
	body := helpers.code_window(lines, k + 1, 0, 6)
	not regex.match(_py_body_check, body)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?mi)^\s*@\s*[\w.]+\.(route|get|post|put|patch|delete|api_route)\(\s*[rfu]?["'][^"']*admin`, content)
	not _py_project_guard
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@")
	m := regex.find_all_string_submatch_n(_py_route, line, 1)
	count(m) > 0
	regex.match(_admin_path, m[0][2])
	_py_finding(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Admin route %s has no authentication decorator or check", [m[0][2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Express / Koa ───────────────────────────────────────────────────────

_js_route := "^\\s*(?:\\w+\\.)*(?:app|router|\\w+Router|\\w+_router|api|server)\\.(?:get|post|put|patch|delete|del|all)\\(\\s*['\"`]([^'\"`]*)['\"`]\\s*,(.*)$"

# Names of middleware that enforce authentication, as the last identifier
# segment (security.isAuthorized(), passport.authenticate('jwt')). A name that
# merely contains "auth" (updateAuthenticatedUsers) is not enforcement.
_guard_seg := `(?:^|[.\s(,\[])(?:requireAuth\w*|requireLogin|requireUser|ensureAuth\w*|ensureLoggedIn|ensureAdmin|isAuthenticated|isLoggedIn|authenticate|authorize|isAuthorized|expressjwt|expressJwt|jwt|checkJwt|verifyToken|verifyJwt|protect|requireAdmin|isAdmin|adminOnly|auth|authMiddleware|authenticated|checkAdmin|requireRole|hasRole)\s*[(,)]`

_use_re := "\\.use\\(\\s*(?:['\"`]([^'\"`]*)['\"`]\\s*,)?(.*)$"

# .use(...) lines of the project that mount a guard: [prefix or "", ...]
_js_guards contains prefix if {
	some p, c in input.file_contents
	_is_js(p)
	not helpers.is_test_path(p)
	contains(c, ".use(")
	some line in split(c, "\n")
	contains(line, ".use(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_use_re, line, 1)
	count(m) > 0
	regex.match(_guard_seg, m[0][2])
	prefix := m[0][1]
}

# The route is under a guarded prefix, or a global guard is mounted.
_js_guarded(route) if "" in _js_guards

_js_guarded(route) if {
	some prefix in _js_guards
	prefix != ""
	startswith(route, prefix)
}

# Collapse nested call parentheses so a top-level comma means a second argument.
_flatten(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, ""), `\([^()]*\)`, ""), `\([^()]*\)`, "")

# The handler is the only argument after the path.
_single_handler(rest) if {
	r := trim_space(rest)
	regex.match(`^(async\s+)?(\(|function\b|\w+\s*=>)`, r)
}

_single_handler(rest) if {
	r := trim_space(_flatten(rest))
	regex.match(`^[\w.$]+\s*\)\s*;?\s*$`, r)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	regex.match(`(?mi)\.(get|post|put|patch|delete|del|all)\(\s*['"\x60][^'"\x60]*admin`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "dmin")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_js_route, line, 1)
	count(m) > 0
	regex.match(_admin_path, m[0][1])
	not _js_guarded(m[0][1])
	_single_handler(m[0][2])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Admin route %s is registered without authentication middleware", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The call broken across lines: router.post(\n  '/admin/x',\n  handler
_js_route_open := `^\s*(?:\w+\.)*(?:app|router|\w+Router|\w+_router|api|server)\.(?:get|post|put|patch|delete|del|all)\(\s*$`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not helpers.is_test_path(path)
	regex.match(`(?mi)\.(get|post|put|patch|delete|del|all)\(\s*\n\s*['"\x60][^'"\x60]*admin`, content)
	lines := split(content, "\n")
	some i, line in lines
	endswith(trim_space(line), "(")
	regex.match(_js_route_open, line)
	j := helpers.next_code_index(lines, i, 2)
	m := regex.find_all_string_submatch_n("^\\s*['\"`]([^'\"`]*)['\"`]\\s*,(.*)$", lines[j], 1)
	count(m) > 0
	regex.match(_admin_path, m[0][1])
	not _js_guarded(m[0][1])
	rest := _rest_after_path(lines, j, m[0][2])
	_single_handler(rest)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Admin route %s is registered without authentication middleware", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_rest_after_path(lines, j, r) := r if trim_space(r) != ""

_rest_after_path(lines, j, r) := lines[k] if {
	trim_space(r) == ""
	k := helpers.next_code_index(lines, j, 2)
}
