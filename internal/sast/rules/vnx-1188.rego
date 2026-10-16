# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1188

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1188",
	"name": "Initialization of a Resource with an Insecure Default",
	"description": "Reports a security setting that is initialised to its insecure value whenever nobody configures it. Python: a top-level DEBUG = True in a settings module that is not a development/local/test settings file, and an environment or config read (os.environ.get, os.getenv, os.environ.setdefault, decouple config(), django-environ env()/env.bool()) whose fallback value turns on a debug/insecure switch (DEBUG as the last word of the name, DEBUG_MODE, ALLOW_INSECURE, SKIP_TLS_VERIFY, DISABLE_AUTH, DISABLE_CSRF, NO_AUTH, CORS_ALLOW_ALL ...) or turns off a protection (VERIFY_SSL, TLS_VERIFY, CHECK_CERT, REQUIRE_AUTH, AUTH_ENABLED, CSRF_ENABLED, SECURE_COOKIES, SESSION_COOKIE_SECURE, SECURE_SSL_REDIRECT, HTTPS_ONLY, COOKIE_SECURE, REJECT_UNAUTHORIZED ...). Pydantic BaseSettings: a bool field declared directly in a class deriving from BaseSettings whose default is the insecure value (debug: bool = True, verify_ssl: bool = False). JavaScript/TypeScript: process.env.NAME || value or ?? value with the same insecure fallback, a destructuring default from process.env (const { DEBUG = 'true' } = process.env), process.env.INSECURE_SWITCH !== 'false' (on unless disabled) and process.env.PROTECTION === 'true' (off unless enabled). Not reported: a secure fallback (DEBUG defaulting to False, VERIFY_SSL defaulting to True), a read with no fallback, non-boolean settings, names that configure a debug tool rather than a debug mode (DEBUG_COLORS, DEBUG_PORT), a read quoted inside a string literal, a BaseSettings subclass of a project base class (the base is not followed), DEBUG = True in dev/local/test settings files or indented inside a class or docstring, comments, strings and test files. DEBUG turned on in a Django deployment settings module (DEBUG = True, or DEBUG read from the environment with a true default) is reported by VNX-PY-006, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1188/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1188],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["insecure-default", "cwe-1188"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A switch that is dangerous when on.
_insecure_name(n) if regex.match(`(?i)(?:^|_)DEBUG(?:_?MODE|_ENABLED|_ON)?$`, n)

# DEBUG_COLORS, DEBUG_PORT and the like configure the debug module, not a
# debug mode, so DEBUG only counts as the last word of the name.
_insecure_name(n) if regex.match(`(?i)(?:^|_)(?:INSECURE|SKIP_(?:TLS_|SSL_|CERT_)?VERIF(?:Y|ICATION)|DISABLE_(?:AUTH|AUTHENTICATION|CSRF|SSL|TLS|VERIFY)|NO_AUTH|ALLOW_ANONYMOUS|CORS_ALLOW_ALL(?:_ORIGINS)?)(?:_|$)`, n)

# A protection that is dangerous when off.
_secure_name(n) if {
	regex.match(`(?i)(?:^|_)(?:VERIFY(?:_SSL|_TLS|_CERTS?)?|SSL_VERIFY|TLS_VERIFY|CHECK_CERTS?|REQUIRE_(?:AUTH|HTTPS|SSL|TLS)|AUTH_ENABLED|CSRF_(?:ENABLED|PROTECTION)|SECURE_COOKIES?|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|(?:COOKIES?|SESSION)_SECURE|(?:TLS_)?REJECT_UNAUTHORI[SZ]ED|SECURE_SSL_REDIRECT|HTTPS_ONLY|ENFORCE_HTTPS)$`, n)
	not _insecure_name(n)
}

_on(v) if regex.match(`^(?:True|true|1|["'](?:true|True|TRUE|1|yes|on)["'])$`, v)

_off(v) if regex.match(`^(?:False|false|0|["'](?:false|False|FALSE|0|no|off)["'])$`, v)

_insecure_fallback(n, v) if {
	_insecure_name(n)
	_on(v)
}

_insecure_fallback(n, v) if {
	_secure_name(n)
	_off(v)
}

# ── Python ──────────────────────────────────────────────────────────────

_py_read := `(?:\benviron\.(?:get|setdefault)|\bgetenv|\bconfig|\benv(?:\.bool|\.str)?)\(\s*["']([A-Za-z0-9_]+)["']\s*,\s*(?:default\s*=\s*)?([^,)\s]+)`

_py_open := `(?:\benviron\.(?:get|setdefault)|\bgetenv|\bconfig|\benv(?:\.bool|\.str)?)\(\s*$`

_dev_settings(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	regex.match(`(?:^|[_.-])(?:dev|devel|develop|development|local|test|tests|testing|ci)(?:[_.-]|$)`, trim_suffix(base, ".py"))
}

_py_call_text(lines, i) := t if {
	regex.match(_py_open, lines[i])
	i + 1 < count(lines)
	t := concat("", [lines[i], trim_space(lines[i + 1])])
} else := lines[i]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`environ|getenv|config\(|env\.|env\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`environ|getenv|config\(|env`, line)
	not helpers.is_comment_line(line)
	text := _py_call_text(lines, i)
	some m in regex.find_all_string_submatch_n(_py_read, text, -1)
	_outside_string(text, m[0])
	_insecure_fallback(m[1], m[2])
	not _py006_reports(path, content, line)
	finding := _finding(path, i, line, sprintf("%s falls back to %s when it is not configured, which is the insecure setting: an unset variable in production silently weakens the deployment. Default to the safe value and opt out explicitly", [m[1], m[2]]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^DEBUG\s*=\s*True\b`, content)
	not helpers.is_test_path(path)
	not _dev_settings(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^DEBUG\s*=\s*True\b`, line)
	not _py006_reports(path, content, line)
	finding := _finding(path, i, line, "DEBUG = True is committed as the module's setting, so the deployment that uses it shows tracebacks, settings and SQL to visitors. Read it from the environment with False as the default")
}

# ── Django DEBUG belongs to VNX-PY-006 ──────────────────────────────────
#
# A DEBUG line that VNX-PY-006 reports (a Django deployment settings module,
# not a dev module, not a base module a sibling overrides) is the same defect
# and is left to it. These mirror VNX-PY-006's own conditions exactly, so a
# line either rule reported before is still reported by one of them.

_py006_base(path) := parts[count(parts) - 1] if parts := split(path, "/")

_py006_parent(path) := parts[count(parts) - 2] if {
	parts := split(path, "/")
	count(parts) > 1
}

_py006_dir(path) := concat("/", array.slice(parts, 0, count(parts) - 1)) if {
	parts := split(path, "/")
	count(parts) > 1
}

_py006_dir(path) := "." if not contains(path, "/")

_py006_in_pkg(path) if _py006_parent(path) == "settings"

_py006_django(content) if regex.match(`(?m)^\s*(?:INSTALLED_APPS|ROOT_URLCONF|MIDDLEWARE|SECRET_KEY|ALLOWED_HOSTS|DATABASES)\s*=|\bdjango\b`, content)

_py006_settings(path, _) if {
	_py006_in_pkg(path)
	_py006_base(path) != "__init__.py"
}

_py006_settings(path, content) if {
	regex.match(`^(?:settings|settings_\w+|\w+_settings)\.py$`, _py006_base(path))
	_py006_django(content)
}

_py006_settings(path, content) if {
	_py006_base(path) == "__init__.py"
	_py006_in_pkg(path)
	_py006_django(content)
}

_py006_dev(path) if regex.match(`(?i)^(?:settings_|.*_)?(?:dev|devel|develop|development|local|test|tests|testing|ci|debug|sandbox)(?:_\w+)?(?:_settings)?\.py$`, _py006_base(path))

_py006_env_true := `^DEBUG\s*(?::\s*bool\s*)?=.*\b(?:get|getenv|bool|config|env)\s*\(\s*["']\w+["']\s*,\s*(?:default\s*=\s*)?(?:True|["'](?:1|[Tt]rue|TRUE|[Yy]es|on)["'])\s*[,)]`

_py006_on(line) if regex.match(`^DEBUG\s*(?::\s*bool\s*)?=\s*True\b`, line)

_py006_on(line) if regex.match(_py006_env_true, line)

_py006_on_text(c) if regex.match(`(?m)^DEBUG\s*=\s*True\b`, c)

_py006_on_text(c) if regex.match(concat("", ["(?m)", _py006_env_true]), c)

_py006_overridden(path) if {
	_py006_in_pkg(path)
	dir := _py006_dir(path)
	some other, c in input.file_contents
	other != path
	endswith(other, ".py")
	_py006_dir(other) == dir
	not _py006_dev(other)
	regex.match(`(?m)^DEBUG\s*=`, c)
	not _py006_on_text(c)
}

_py006_reports(path, content, line) if {
	startswith(line, "DEBUG")
	_py006_on(line)
	_py006_settings(path, content)
	not _py006_dev(path)
	not _py006_overridden(path)
}

# ── JavaScript / TypeScript ─────────────────────────────────────────────

_is_js(path) if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_js_read := `process\.env(?:\.([A-Za-z_]\w*)|\[\s*["']([A-Za-z_]\w*)["']\s*\])\s*(\|\||\?\?|===|!==|==|!=)\s*([^,;)\s}]+)`

_js_insecure(n, op, v) if {
	op in {"||", "??"}
	_insecure_fallback(n, v)
}

_js_insecure(n, op, v) if {
	op in {"!==", "!="}
	_insecure_name(n)
	_off(v)
}

_js_insecure(n, op, v) if {
	op in {"===", "=="}
	_secure_name(n)
	_on(v)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "process.env")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "process.env")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_js_read, line, -1)
	_outside_string(line, m[0])
	n := concat("", [m[1], m[2]])
	_js_insecure(n, m[3], m[4])
	finding := _finding(path, i, line, sprintf("process.env.%s resolves to the insecure setting when the variable is unset (%s %s). Make the safe value the default and require an explicit opt-out", [n, m[3], m[4]]))
}

# The match does not start inside a string literal: an even number of each
# quote character precedes it. A help text quoting the insecure read is prose.
_outside_string(text, s) if {
	idx := indexof(text, s)
	idx >= 0
	pre := substring(text, 0, idx)
	count(regex.find_all_string_submatch_n(`"`, pre, -1)) % 2 == 0
	count(regex.find_all_string_submatch_n(`'`, pre, -1)) % 2 == 0
	count(regex.find_all_string_submatch_n("`", pre, -1)) % 2 == 0
}

# const { DEBUG = 'true', PORT = 3000 } = process.env;
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\}\s*=\s*process\.env\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "process.env")
	not helpers.is_comment_line(line)
	some d in regex.find_all_string_submatch_n(`\{([^{}]*)\}\s*=\s*process\.env\b`, line, -1)
	_outside_string(line, d[0])
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*=\s*([^,}\s]+)`, d[1], -1)
	_insecure_fallback(m[1], m[2])
	finding := _finding(path, i, line, sprintf("%s is destructured from process.env with the default %s, the insecure setting, so an unset variable silently weakens the deployment. Default to the safe value", [m[1], m[2]]))
}

# Pydantic BaseSettings: a field default is what the deployment gets when the
# environment does not set it.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "BaseSettings")
	not helpers.is_test_path(path)
	not _dev_settings(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "bool")
	m := regex.find_all_string_submatch_n(`^\s+([A-Za-z_]\w*)\s*:\s*(?:bool|StrictBool)\s*=\s*(True|False)\s*(?:#.*)?$`, line, 1)
	count(m) > 0
	_insecure_fallback(m[0][1], m[0][2])
	_in_base_settings(lines, i)
	finding := _finding(path, i, line, sprintf("The settings field %s defaults to %s, the insecure value, so a deployment that does not set it in the environment runs weakened. Make the safe value the default", [m[0][1], m[0][2]]))
}

_in_base_settings(lines, i) if {
	starts := [k | some k in numbers.range(max([0, i - 80]), i - 1); regex.match(`^class\s+\w+`, lines[k])]
	count(starts) > 0
	regex.match(`^class\s+\w+\s*\([^)]*BaseSettings`, lines[max(starts)])
}
