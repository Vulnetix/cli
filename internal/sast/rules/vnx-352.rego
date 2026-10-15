# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_352

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-352",
	"name": "Cross-Site Request Forgery protection disabled (Django, Flask-WTF, Node.js, Rails)",
	"description": "A web framework's built-in Cross-Site Request Forgery protection is switched off, so a page on another site can submit state-changing requests with the victim's cookies. Reported: Python Django @csrf_exempt, method_decorator(csrf_exempt, ...) and csrf_exempt(view), a Django MIDDLEWARE/MIDDLEWARE_CLASSES list that does not include django.middleware.csrf.CsrfViewMiddleware (commented out counts as absent; MIDDLEWARE += / .insert / .append of it elsewhere in the file counts as present; a list that splices in another list, such as *BASE_MIDDLEWARE, is not judged), Flask-WTF WTF_CSRF_ENABLED = False or WTF_CSRF_CHECK_DEFAULT = False (class attribute, app.config[...] assignment, or a WTF_CSRF_ENABLED=False keyword to app.config.update/from_mapping), @csrf.exempt, a FlaskForm Meta with csrf = False and meta={'csrf': False}; Node.js csrf: false in an object literal (lusca, Sails config/security.js and similar), SvelteKit/Astro checkOrigin: false, Apollo Server csrfPrevention: false and csurf ignoreMethods listing POST, PUT, PATCH or DELETE (on one line or an array spread over the following lines); Ruby on Rails skip_before_action (or the Rails 4 skip_before_filter) naming :verify_authenticity_token among its filters, protect_from_forgery except:/only: (protection skipped for the other actions), skip_forgery_protection, config.action_controller.allow_forgery_protection = false outside config/environments/test.rb, and an ApplicationController < ActionController::Base with no protect_from_forgery in a project whose config/application.rb neither calls load_defaults 5.2 or later nor sets default_protect_from_forgery. Not reported: settings inside a class whose name contains Test or under an if testing branch, test files, the import of csrf_exempt, csrf_protect/ensure_csrf_cookie, the words inside string literals and comments, ActionController::API controllers, and Spring (VNX-JAVA-010) or ASP.NET (VNX-CS-005), which have their own rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-352/",
	"languages": ["node", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [352],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["csrf", "cwe-352"],
}

_js_exts := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

_is_js(path) if {
	some e in _js_exts
	endswith(path, e)
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if endswith(path, ".min.js")

_skip(path) if regex.match(`(^|/)(conftest\.py|tests?\.py|[^/]*_tests?\.py)$`, path)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Text of a line with string literals blanked, so a message naming the
# setting is not the setting.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, `""`)

# ── Python ──────────────────────────────────────────────────────────────

_py_patterns := [
	[`^\s*@csrf_exempt\b`, "Django view decorated with @csrf_exempt: CSRF protection is off for this view"],
	[`\bmethod_decorator\(\s*csrf_exempt\b`, "Django class-based view wrapped in csrf_exempt: CSRF protection is off for this view"],
	[`(?:=|\(|,|^)\s*csrf_exempt\(\s*[A-Za-z_]`, "Django view wrapped in csrf_exempt(): CSRF protection is off for this view"],
	[`^\s*@[A-Za-z_]\w*\.exempt\b`, "Flask-WTF @csrf.exempt: CSRF protection is off for this view"],
	[`^\s*WTF_CSRF_(?:ENABLED|CHECK_DEFAULT)\s*=\s*False\b`, "Flask-WTF CSRF protection switched off (WTF_CSRF_ENABLED/WTF_CSRF_CHECK_DEFAULT = False)"],
	[`[\(,]\s*WTF_CSRF_(?:ENABLED|CHECK_DEFAULT)\s*=\s*False\b`, "Flask-WTF CSRF protection switched off (WTF_CSRF_ENABLED=False passed to app.config.update/from_mapping)"],
]

_py_hit(_, _, line, _) := msg if {
	some p in _py_patterns
	regex.match(p[0], line)
	msg := p[1]
}

# app.config["WTF_CSRF_ENABLED"] = False (the key is read from the raw line).
_py_hit(_, _, line, raw) := "Flask-WTF CSRF protection switched off (app.config[\"WTF_CSRF_ENABLED\"] = False)" if {
	regex.match(`\.config\s*\[\s*""\s*\]\s*=\s*False\b`, line)
	regex.match(`\[\s*["']WTF_CSRF_(?:ENABLED|CHECK_DEFAULT)["']\s*\]`, raw)
}

_py_hit(_, _, line, raw) := "Flask-WTF form created with meta={'csrf': False}: CSRF protection is off for this form" if {
	regex.match(`\bmeta\s*=\s*\{\s*""\s*:\s*False`, line)
	regex.match(`\{\s*["']csrf["']\s*:`, raw)
}

# class Meta: csrf = False (Flask-WTF / WTForms SecureForm)
_py_hit(lines, i, line, _) := "Flask-WTF form Meta sets csrf = False: CSRF protection is off for this form" if {
	regex.match(`^\s+csrf\s*=\s*False\b`, line)
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*class\s+Meta\b`, lines[j])
}

# The nearest enclosing class above line i (within 40 lines, Meta aside) is a
# test configuration, or an `if ... testing` branch opens just above.
_in_test_scope(lines, i) if {
	start := max([0, i - 40])
	classes := [j |
		some j in numbers.range(start, i)
		regex.match(`^\s*class\s+\w+`, lines[j])
		not regex.match(`^\s*class\s+Meta\b`, lines[j])
	]
	count(classes) > 0
	regex.match(`^\s*class\s+\w*(?i:test)`, lines[max(classes)])
}

_in_test_scope(lines, i) if {
	start := max([0, i - 2])
	some j in numbers.range(start, i)
	regex.match(`(?i)^\s*(if|elif)\b.*\btest(ing)?\b`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	contains(lower(content), "csrf")
	lines := split(content, "\n")
	some i, raw in lines
	contains(lower(raw), "csrf")
	not helpers.is_comment_line(raw)
	line := _code(raw)
	msg := _py_hit(lines, i, line, raw)
	not _in_test_scope(lines, i)
	finding := _finding(path, i, raw, msg)
}

# Django MIDDLEWARE list with no CsrfViewMiddleware.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not _skip(path)
	contains(content, "django.")
	regex.match(`(?m)^MIDDLEWARE(?:_CLASSES)?\s*=\s*[\[\(]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^MIDDLEWARE(?:_CLASSES)?\s*=\s*[\[\(]`, line)
	end := _list_end(lines, i)
	body := helpers.code_window(lines, i, 0, end - i)
	contains(body, "django.")
	contains(body, "Middleware")
	not contains(body, "CsrfViewMiddleware")

	# the list splices in another list (*BASE_MIDDLEWARE, base.MIDDLEWARE + [...]) that may carry it
	not regex.match(`(?m)^\s*\*\s*[A-Za-z_]|[\]\)]\s*\+\s*[A-Za-z_]|[A-Za-z_][\w.]*\s*\+\s*[\[\(]`, concat("\n", array.slice(lines, i, end + 1)))

	# added to the list elsewhere in the file (MIDDLEWARE += [...], .insert, .append)
	not regex.match(`(?m)^[^#\n]*\bMIDDLEWARE(?:_CLASSES)?\b[^#\n]*(?:\+=|\.insert\(|\.append\(|\.extend\()[^#\n]*CsrfViewMiddleware`, content)
	finding := _finding(path, i, line, "Django MIDDLEWARE does not include django.middleware.csrf.CsrfViewMiddleware: no view is protected against CSRF")
}

_list_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 40])
	ends := [k | some k in numbers.range(i, last); regex.match(`^\s*[\]\)]`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# ── Node.js ─────────────────────────────────────────────────────────────

_js_hit(code) := "CSRF protection switched off (csrf: false)" if {
	regex.match(`(?:^|[\{,\s])csrf\s*:\s*false\b`, code)
}

_js_hit(code) := "Apollo Server CSRF prevention switched off (csrfPrevention: false): simple cross-site GraphQL requests are executed" if {
	regex.match(`(?:^|[\{,\s])csrfPrevention\s*:\s*false\b`, code)
}

_js_hit(code) := "Origin check for form submissions switched off (checkOrigin: false): cross-site POSTs are accepted" if {
	regex.match(`(?:^|[\{,\s])checkOrigin\s*:\s*false\b`, code)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	regex.match(`(csrf|csrfPrevention|checkOrigin)["']?\s*:\s*false`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(csrf|csrfPrevention|checkOrigin)["']?\s*:\s*false`, line)
	not helpers.is_comment_line(line)

	# unquote a quoted key, then blank the remaining string literals
	code := _code(regex.replace(line, `["'](csrf|csrfPrevention|checkOrigin)["']\s*:`, "$1:"))
	msg := _js_hit(code)
	finding := _finding(path, i, line, msg)
}

# csurf({ ignoreMethods: [..., 'POST', ...] })
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	contains(content, "ignoreMethods")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ignoreMethods")
	not helpers.is_comment_line(line)
	_ignore_list(lines, i, line)
	finding := _finding(path, i, line, "csurf ignoreMethods lists a state-changing method: those requests are not checked for a CSRF token")
}

# The ignoreMethods array, on this line or continued over the next ten.
_ignore_list(_, _, line) if regex.match(`ignoreMethods\s*:\s*\[[^\]]*["'](?i:post|put|patch|delete)["']`, line)

_ignore_list(lines, i, line) if {
	regex.match(`ignoreMethods\s*:\s*\[[^\]]*$`, line)
	tail := concat("\n", array.slice(lines, i + 1, i + 11))
	m := regex.find_n(`^[^\]]*\]`, tail, 1)
	count(m) > 0
	regex.match(`["'](?i:post|put|patch|delete)["']`, m[0])
}

# ── Ruby on Rails ───────────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	not _skip(path)
	regex.match(`verify_authenticity_token|forgery_protection|protect_from_forgery`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`verify_authenticity_token|forgery_protection|protect_from_forgery`, line)
	not helpers.is_comment_line(line)
	msg := _rb_hit(path, line)
	finding := _finding(path, i, line, msg)
}

_rb_hit(_, line) := "Rails CSRF check skipped (skip_before_action :verify_authenticity_token)" if {
	regex.match(`^\s*skip_before_(?:action|filter)\s*\(?\s*(?::\w+[!?]?\s*,\s*)*:verify_authenticity_token\b`, line)
}

_rb_hit(_, line) := "Rails CSRF check skipped for some actions (protect_from_forgery except:/only:)" if {
	regex.match(`^\s*protect_from_forgery\b.*\b(?:except|only)\s*:`, line)
}

_rb_hit(_, line) := "Rails CSRF check skipped (skip_forgery_protection)" if {
	regex.match(`^\s*skip_forgery_protection\b`, line)
}

_rb_hit(path, line) := "Rails forgery protection switched off (allow_forgery_protection = false)" if {
	regex.match(`\ballow_forgery_protection\s*=\s*false\b`, line)
	not endswith(path, "environments/test.rb")
}

# ApplicationController without protect_from_forgery, on a Rails
# configuration that does not turn it on by default.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, "app/controllers/application_controller.rb")
	not regex.match(`(?m)^\s*protect_from_forgery\b`, content)
	some app_path, app in input.file_contents
	endswith(app_path, "config/application.rb")
	contains(app, "Rails::Application")
	not _rails_default_protection(app)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*class\s+ApplicationController\s*<\s*ActionController::Base\b`, line)
	finding := _finding(path, i, line, "ApplicationController inherits ActionController::Base without protect_from_forgery, and config/application.rb does not enable it by default (load_defaults 5.2+): no controller verifies CSRF tokens")
}

_rails_default_protection(app) if {
	m := regex.find_all_string_submatch_n(`(?m)^\s*config\.load_defaults\s+["']?(\d+)\.(\d+)`, app, 1)
	count(m) > 0
	(to_number(m[0][1]) * 100) + to_number(m[0][2]) >= 502
}

_rails_default_protection(app) if regex.match(`(?m)^\s*config\.action_controller\.default_protect_from_forgery\s*=\s*true`, app)
