# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_799

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-799",
	"name": "Authentication endpoint without attempt-rate control",
	"description": "Reports the registration of a credential-checking HTTP route (a path segment login, log-in, signin, sign-in, logon, token, otp, verify-otp, 2fa, mfa, authenticate, reset-password, forgot-password or password-reset, or a segment ending in login/signin/logon such as devlogin or admin-login) that accepts POST: Express/Koa-style routers (app/router/server/fastify .post/.all, including an array of paths and a Koa named route), a chained router.route('/login').post(...), a hapi or fastify route object (server.route({ method: 'POST', path: '/login' })), NestJS @Post/@All, Flask @app.route(..., methods=[...POST...]) and @bp.post, FastAPI @app.post/@router.post, and Django path()/re_path() in urls.py. It is reported only when nothing limits how often it can be tried: no limiter, brute-force or throttle middleware on the route itself (loginLimiter, brute.prevent, @limiter.limit, @Throttle, RateLimiter dependency, a django-ratelimit @ratelimit decorator on the view the urls.py entry names), no app-wide limiter in the project (app.use(limiter|rateLimit(...)), koa-ratelimit, @fastify/rate-limit, rate-limiter-flexible, NestJS ThrottlerGuard, flask-limiter or slowapi default_limits, django-axes, django-ratelimit middleware), no path-scoped app.use('<prefix>', rateLimit(...)) covering the route, and no account-lockout bookkeeping (failedLoginAttempts, lockedUntil, lockout). Not reported: GET-only routes, other paths, commented or quoted routes, client calls (axios.post, api.post), test and example files. A limiter enforced by a reverse proxy or API gateway is invisible to this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-799/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [799],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-control-of-interaction-frequency", "cwe-799", "brute-force", "rate-limiting"],
}

_js_ext := {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

_is_js(path) if {
	some e in _js_ext
	endswith(path, e)
}

_is_py(path) if endswith(path, ".py")

_in_scope(path) if _is_js(path)

_in_scope(path) if _is_py(path)

_excluded(path) if helpers.is_test_path(path)

_excluded(path) if regex.match(`(^|/)(examples?|samples?|docs?|node_modules|vendor|dist|build)/`, path)

_excluded(path) if endswith(path, ".min.js")

_excluded(path) if endswith(path, ".d.ts")

# A credential-checking path segment.
_sensitive_path(p) if regex.match(`(?i)(^|[/^])(login|log-in|log_in|signin|sign-in|sign_in|logon|token|otp|verify-otp|verify_otp|2fa|mfa|authenticate|reset-password|reset_password|forgot-password|forgot_password|password-reset|password_reset)(/|$|\?|\.|\$)`, p)

# A segment that ends in login/signin/logon (devlogin, adminLogin, user_signin).
_sensitive_path(p) if regex.match(`(?i)(^|[/^])[a-z0-9]+[-_]?(login|signin|logon)(/|$|\?|\.|\$)`, p)

# Route registration line shapes. Each returns the kind of route.
_route_kind(path, line) := "js" if {
	_is_js(path)
	regex.match(`^\s*(?:app|router|server|fastify|routes|[A-Za-z_$][\w$]*[Rr]outer)\s*\.\s*(?:post|all)\s*\(`, line)
}

# router.route('/login').post(...), the .post possibly on a following line.
_route_kind(path, line) := "jschain" if {
	_is_js(path)
	regex.match(`^\s*(?:app|router|server|routes|[A-Za-z_$][\w$]*[Rr]outer)\s*\.\s*route\s*\(\s*['"\x60]`, line)
}

# hapi / fastify route objects: server.route({ method: 'POST', path: '/login' }).
_route_kind(path, line) := "jsobj" if {
	_is_js(path)
	regex.match(`^\s*(?:server|app|fastify|router|[A-Za-z_$][\w$]*[Ss]erver)\s*\.\s*route\s*\(\s*\{?\s*(?:$|(?:method|path|url)\b)`, line)
}

_route_kind(path, line) := "nest" if {
	_is_js(path)
	regex.match(`^\s*@(?:Post|All)\s*\(\s*['"\x60]`, line)
}

_route_kind(path, line) := "pypost" if {
	_is_py(path)
	regex.match(`^\s*@\s*[A-Za-z_]\w*\s*\.\s*post\s*\(`, line)
}

_route_kind(path, line) := "pyroute" if {
	_is_py(path)
	regex.match(`^\s*@\s*[A-Za-z_]\w*\s*\.\s*route\s*\(`, line)
}

_route_kind(path, line) := "django" if {
	_is_py(path)
	regex.match(`(^|/)urls\.py$`, path)
	regex.match(`^\s*(?:re_path|path|url)\s*\(\s*r?['"]`, line)
}

_window(lines, i, n) := concat("\n", array.slice(lines, i, min([count(lines), i + n])))

# The candidate paths of a route: the first string argument and, for a Koa
# named route or an array of paths, the second; a route object's path/url.
_route_paths("jsobj", win) := {p |
	some m in regex.find_all_string_submatch_n(`\b(?:path|url)\s*:\s*['"\x60]([^'"\x60\n]*)['"\x60]`, win, 1)
	p := m[1]
}

_route_paths(kind, win) := ps if {
	kind != "jsobj"
	ps := _arg_paths(win)
}

_arg_paths(win) := {p |
	some m in regex.find_all_string_submatch_n(`\(\s*\[?\s*r?['"\x60]([^'"\x60\n]*)['"\x60](?:\s*,\s*['"\x60]([^'"\x60\n]*)['"\x60])?`, win, 1)
	some p in [m[1], m[2]]
	p != ""
}

_win_len("jsobj") := 8

_win_len(kind) := 3 if kind != "jsobj"

# The chained form accepts POST when a .post/.all follows before the next route.
_chain_post(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 15]))
	regex.match(`(?:^\s*|\)\s*)\.\s*(?:post|all)\s*\(`, lines[k])
	not _route_between(lines, i, k)
}

_route_between(lines, i, k) if {
	k > i
	some m in numbers.range(i + 1, k)
	regex.match(`\.\s*route\s*\(`, lines[m])
}

_obj_post(lines, i) if regex.match(`(?i)\bmethod\s*:\s*(?:\[[^\]]*)?['"\x60](?:POST|\*)['"\x60]`, _window(lines, i, 8))

_kind_accepts_post("jschain", lines, i) if _chain_post(lines, i)

_kind_accepts_post("jsobj", lines, i) if _obj_post(lines, i)

_kind_accepts_post(kind, lines, i) if {
	not kind in {"jschain", "jsobj"}
	_accepts_post(kind, _py_decorators(lines, i))
}

# Text of a Python decorator stack from line i to the def.
_py_decorators(lines, i) := concat("\n", [l |
	some k in numbers.range(i, min([count(lines) - 1, i + 6]))
	l := lines[k]
	not _past_def(lines, i, k)
])

_past_def(lines, i, k) if {
	some m in numbers.range(i, k - 1)
	regex.match(`^\s*(async\s+)?def\s`, lines[m])
}

_accepts_post("js", _) := true

_accepts_post("nest", _) := true

_accepts_post("pypost", _) := true

_accepts_post("django", _) := true

_accepts_post("pyroute", dec) if regex.match(`(?is)methods\s*=\s*[\[(\{][^\])\}]*['"]POST['"]`, dec)

# Limiter wired onto the route itself.
_route_limited(lines, i, "pyroute") if regex.match(_limit_word, _py_decorators(lines, i))

_route_limited(lines, i, "pypost") if regex.match(_limit_word, _py_decorators(lines, i))

_route_limited(lines, i, kind) if {
	kind in {"js", "django"}
	regex.match(_limit_word, _window(lines, i, 4))
}

_route_limited(lines, i, kind) if {
	kind in {"jschain", "jsobj"}
	regex.match(_limit_word, _window(lines, i, 10))
}

# Django: the view a urls.py entry names carries a ratelimit decorator.
_route_limited(lines, i, "django") if {
	m := regex.find_all_string_submatch_n(`\(\s*r?['"][^'"]*['"]\s*,\s*([\w.]+)`, _window(lines, i, 3), 1)
	name := _view_name(split(m[0][1], "."))
	some path, content in input.file_contents
	_is_py(path)
	contains(content, "ratelimit")
	vl := split(content, "\n")
	some k, l in vl
	contains(l, name)
	regex.match(concat("", [`^\s*(?:async\s+)?(?:def|class)\s+`, name, `\b`]), l)
	some d in numbers.range(max([0, k - 6]), k)
	regex.match(`^\s*@\s*(?:\w+\.)?(?:ratelimit|method_decorator\s*\(\s*ratelimit)`, vl[d])
}

_view_name(parts) := parts[count(parts) - 1] if parts[count(parts) - 1] != "as_view"

_view_name(parts) := parts[count(parts) - 2] if {
	parts[count(parts) - 1] == "as_view"
	count(parts) > 1
}

_route_limited(lines, i, "nest") if {
	some k in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 2]))
	regex.match(`@(?:Throttle|UseGuards\s*\([^)]*Throttler)`, lines[k])
}

_limit_word := `(?i)(limit|brute|throttl|slow_?down|ratelimit)`

# Project-wide controls.
_global_re := `(?m)(\.use\s*\(\s*[\w$.]*(?i:limit|brute|throttl|slowdown)|@fastify/rate-limit|fastify-rate-limit|rate-limiter-flexible|RateLimiter(?:Memory|Redis|Mongo|Postgres)|ThrottlerGuard|default_limits\s*=|application_limits\s*=|SlowAPIMiddleware|['"]axes['"]|axes\.middleware|AxesMiddleware|AxesStandaloneBackend|django_ratelimit\.middleware|ratelimit\.middleware)`

_lockout_re := `(?i)(failed_?login_?attempts|login_?attempts|failed_?attempts|locked_?until|lock_?out|account_?locked|max_?failed_?(logins?|attempts)?)\b`

_project_mitigated(_) if {
	some path, content in input.file_contents
	_in_scope(path)
	regex.match(`(?i)limit|throttl|brute|axes|slowdown`, content)
	regex.match(_global_re, content)
}

_project_mitigated(_) if {
	some path, content in input.file_contents
	_in_scope(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)ttempt|ocked|ockout`, content)
	regex.match(_lockout_re, content)
}

_project_mitigated(_) if {
	some path, content in input.file_contents
	regex.match(`(^|/)settings[^/]*\.py$`, path)
	contains(content, "axes")
}

# app.use('/prefix', rateLimit(...)) scopes a limiter to that prefix.
_scoped_prefixes(_) := {p |
	some path, content in input.file_contents
	_is_js(path)
	contains(content, ".use")
	some m in regex.find_all_string_submatch_n(`\.use\s*\(\s*['"\x60]([^'"\x60\n]+)['"\x60]\s*,[^\n]*(?i:limit|brute|throttl|slowdown)`, content, -1)
	p := m[1]
}

_prefix_covered(rp) if {
	some p in _scoped_prefixes(true)
	startswith(rp, p)
}

_cheap_gate(_, content) if contains(content, ".post(")

_cheap_gate(path, content) if {
	_is_js(path)
	contains(content, "@Post(")
}

_cheap_gate(path, content) if {
	_is_js(path)
	contains(content, ".all(")
}

_cheap_gate(_, content) if contains(content, ".route(")

_cheap_gate(path, content) if {
	endswith(path, "urls.py")
	contains(content, "path(")
}

_gate_re := `(?im)(\.(post|all|route)\s*\(|@(Post|All)\s*\(|^\s*(re_)?path\s*\()`

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	not _excluded(path)
	_cheap_gate(path, content)
	regex.match(_gate_re, content)
	regex.match(`(?i)(log.?in|sign.?in|logon|token|otp|2fa|mfa|authenticate|password)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	regex.match(`(?:post|Post|route|path|all|All)\s*\(`, line)
	kind := _route_kind(path, line)
	not helpers.is_comment_line(line)
	win := _window(lines, i, _win_len(kind))
	rps := {p | some p in _route_paths(kind, win); _sensitive_path(p)}
	count(rps) > 0
	rp := min(rps)
	_kind_accepts_post(kind, lines, i)
	not _route_limited(lines, i, kind)
	not _prefix_covered(rp)
	not _project_mitigated(true)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Authentication route %q accepts credentials with no rate limit, throttle or lockout: an attacker can guess passwords or codes as fast as the server answers", [rp]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
