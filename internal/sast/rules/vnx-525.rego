# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_525

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-525",
	"name": "Use of Web Browser Cache Containing Sensitive Information",
	"description": "A response that only an authenticated user should see is explicitly made cacheable, so a shared proxy, CDN or the browser of a shared computer keeps a copy another person can read. Reported in Python: Django @cache_page, Flask-Caching @cache.cached and @cache_control(public=True | max_age=N) stacked with an authentication decorator (@login_required, @permission_required, @user_passes_test, @staff_member_required, @jwt_required, @auth_required, @roles_required); and, in a handler of the same file, response['Cache-Control'] = ..., resp.headers['Cache-Control'] = ... or patch_cache_control(response, public=True | max_age=N). In JavaScript/TypeScript: res.set/setHeader/header/append('Cache-Control', ...). In both, a header object or dict literal ({'Cache-Control': ...}) on a response line. A header value counts when it is public or has a non-zero max-age/s-maxage and says neither private, no-store nor no-cache; it is reported when the handler around it (from its route or function header to the next one) is authenticated or serves user data: an authentication decorator or middleware (requireAuth, ensureAuthenticated, passport.authenticate, LoginRequiredMixin), request.user/current_user/req.user/req.session, a token or password, or a route such as /account, /profile, /me, /settings, /billing, /orders. Not reported: no-store, no-cache and private policies, caching of public views and static assets, comments, strings and test code. A sensitive response with no Cache-Control at all is not reported (whether a response is sensitive is not decidable from the line).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-525/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [525],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["web-browser-cache", "cache-control", "cwe-525"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some e in _js_exts
	endswith(path, e)
	not endswith(path, ".min.js")
}

_auth_deco := `^\s*@(?:\w+\.)?(?:login_required|permission_required|user_passes_test|staff_member_required|superuser_required|jwt_required|fresh_jwt_required|auth_required|roles_required|roles_accepted|requires_auth|authenticated)\b`

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "A response for an authenticated user is marked cacheable, so a shared cache or the browser of a shared machine keeps a copy others can read. Send Cache-Control: no-store (or at least private, no-cache) on authenticated and sensitive responses",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Python caching decorators on an authenticated view ───────────────────

_cache_deco := `^\s*@(?:\w+\.)?(?:cache_page|cached|cache_control)\(|^\s*@method_decorator\(\s*cache_page\(`

_deco_caches(line) if regex.match(`@(?:\w+\.)?(?:cache_page|cached)\(|@method_decorator\(\s*cache_page\(`, line)

_deco_caches(line) if {
	regex.match(`@(?:\w+\.)?cache_control\(`, line)
	_kwargs_cacheable(line)
}

_kwargs_cacheable(s) if {
	regex.match(`\bpublic\s*=\s*True|\b(?:max_age|s_maxage)\s*=\s*[1-9]`, s)
	not regex.match(`\b(?:private|no_store|no_cache)\s*=\s*True`, s)
}

_is_deco(line) if regex.match(`^\s*@`, line)

# The decorator block around line i: contiguous decorator lines above and below.
_block(lines, i) := concat("\n", [lines[j] | some j in numbers.range(_block_start(lines, i), _block_end(lines, i))])

_block_start(lines, i) := s if {
	nondeco := [k | some k in numbers.range(max([0, i - 8]), i); not _is_deco(lines[k])]
	s := max(array.concat([max([0, i - 8]) - 1], nondeco)) + 1
}

_block_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 8])
	nondeco := [k | some k in numbers.range(i, last); not _is_deco(lines[k])]
	e := min(array.concat([last + 1], nondeco)) - 1
}

findings contains f if {
	some path, content in input.file_contents
	_lang(path) == "py"
	regex.match(`@(?:\w+\.)?(?:cache_page|cached|cache_control)\(|cache_page\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@")
	regex.match(_cache_deco, line)
	_deco_caches(line)
	some l in split(_block(lines, i), "\n")
	regex.match(_auth_deco, l)
	f := _finding(path, i, line)
}

# ── Cache-Control set on a sensitive handler's response ──────────────────

_header_values(line) := vs if {
	vs := array.concat(
		[m[2] | some m in regex.find_all_string_submatch_n(`\.(?:set|setHeader|header|append|add)\(\s*['"]Cache-Control['"]\s*,\s*(['"\x60])([^'"\x60]*)`, line, -1)],
		array.concat(
			[m[1] | some m in regex.find_all_string_submatch_n(`\[\s*['"]Cache-Control['"]\s*\]\s*=\s*['"]([^'"]*)`, line, -1)],
			_object_values(line),
		),
	)
}

# Object/dict form of response headers: res.set({...}), res.writeHead(200, {...}),
# Flask's (body, status, {...}) tuple. Outgoing client requests are not responses.
_object_values(line) := [m[1] |
	not regex.match(`\b(?:requests|httpx|axios|fetch|urllib)\b`, line)
	some m in regex.find_all_string_submatch_n(`['"]Cache-Control['"]\s*:\s*['"\x60]([^'"\x60]*)`, line, -1)
]

_value_cacheable(v) if {
	l := lower(v)
	regex.match(`\bpublic\b|max-age\s*=\s*[1-9]|s-maxage\s*=\s*[1-9]`, l)
	not regex.match(`no-store|no-cache|\bprivate\b`, l)
}

_sets_cacheable(line) if {
	some v in _header_values(line)
	_value_cacheable(v)
}

_sets_cacheable(line) if {
	regex.match(`\bpatch_cache_control\(`, line)
	_kwargs_cacheable(line)
}

_handler_start := `^\s*(?:@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete)\(|(?:async\s+)?def\s|(?:router|app|server|api)\.(?:get|post|put|patch|delete|all|use|route)\(|(?:export\s+)?(?:async\s+)?function\b)`

_sensitive := `(?i)\breq\.(?:user|session)\b|isAuthenticated|request\.user\b|\bcurrent_user\b|LoginRequiredMixin|\brequire_?auth\w*|ensure_?auth\w*|isLoggedIn|passport\.authenticate|\b(?:access_?|id_?|api_?|refresh_?)?token\b|\bpassword\b|['"\x60]/(?:api/)?(?:account|profile|me|user|users|settings|billing|invoices?|statements?|wallet|orders?|dashboard)(?:[/?:'"\x60]|\s*$)`

# The handler around line i: from the nearest handler start above (with the
# decorators stacked on it) to just before the next one below.
_handler(lines, i) := txt if {
	lo := max([0, i - 15])
	starts := [k | some k in numbers.range(lo, i); regex.match(_handler_start, lines[k])]
	s0 := max(array.concat([lo], starts))
	s := _decorators_above(lines, s0)
	hi := min([count(lines) - 1, i + 8])
	nexts := [k | some k in numbers.range(i + 1, hi); regex.match(_handler_start, lines[k])]
	e := min(array.concat([hi + 1], nexts)) - 1
	txt := concat("\n", [lines[k] | some k in numbers.range(s, e); not helpers.is_comment_line(lines[k])])
}

_decorators_above(lines, s) := t if {
	decos := [k | some k in numbers.range(max([0, s - 6]), s); _all_deco(lines, k, s)]
	t := min(array.concat([s], decos))
}

_all_deco(lines, k, s) if {
	k < s
	every j in numbers.range(k, s - 1) {
		_is_deco(lines[j])
	}
}

findings contains f if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(`Cache-Control|patch_cache_control`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Cache-Control|patch_cache_control`, line)
	not helpers.is_comment_line(line)
	_sets_cacheable(line)
	h := _handler(lines, i)
	_handler_sensitive(h)
	f := _finding(path, i, line)
}

_handler_sensitive(h) if regex.match(_sensitive, h)

_handler_sensitive(h) if {
	some l in split(h, "\n")
	regex.match(_auth_deco, l)
}
