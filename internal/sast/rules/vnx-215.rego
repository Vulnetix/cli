# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_215

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-215",
	"name": "Insertion of Sensitive Information Into Debugging Code",
	"description": "A debugging facility that shows internal state (stack frames with local variables, source code, request data, SQL, settings, process memory) is switched on unconditionally, so it runs in production for every visitor. Reported: Python cgitb.enable() (also through an import alias, or enable() after from cgitb import enable) unless display is turned off or it sits under an if on DEBUG, the environment or a setting; the Django Debug Toolbar's SHOW_TOOLBAR_CALLBACK set to a lambda that always returns True; Express's errorhandler middleware (the module imported from 'errorhandler', or require('errorhandler')()) mounted with app.use outside a NODE_ENV/app.get('env')/development check (a check that NODE_ENV is production is not one, unless the call is in its else branch), and Express 2/3 or connect's express.errorHandler() with no options or with showStack/dumpExceptions: true under the same condition; the Node.js inspector opened on every interface (--inspect=0.0.0.0 or --inspect-brk=0.0.0.0 in a Dockerfile, package.json script, compose file or shell script, and inspector.open(port, '0.0.0.0')); ASP.NET Core UseDeveloperExceptionPage() and UseDatabaseErrorPage() outside an IsDevelopment()/IsEnvironment()/#if DEBUG check. A guard counts on the same line or on an if/elif, ternary, && or || line up to eight lines above at a shallower indent (a shallower const debug = require('debug') is not a guard); for ASP.NET, !env.IsProduction() also counts. Not reported: the same facilities behind an environment check, cgitb.enable(display=0, logdir=...), a toolbar callback that checks DEBUG or INTERNAL_IPS, --inspect bound to localhost or with no host, a project's own errorHandler middleware, comments, strings and test code. Django DEBUG = True (VNX-PY-006), the Flask/Werkzeug debugger (VNX-PY-008) and Go pprof endpoints (VNX-GO-019) have their own rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-215/",
	"languages": ["node", "python", "csharp", "docker", "bash"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [215],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["debug", "information-exposure", "cwe-215"],
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

_msg_page := "Debug error page enabled unconditionally: in production it shows stack frames, local variables, source and request data to any visitor. Enable it only in development (behind an environment check)"

_msg_inspect := "Node.js inspector listening on every interface: anyone who can reach the port can read process memory (secrets included) and run code. Bind it to 127.0.0.1 and never ship it enabled"

_msg_toolbar := "Debug toolbar shown to every visitor: it exposes SQL, settings, headers and session data. Show it only when DEBUG is on and the client is in INTERNAL_IPS"

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

_base(path) := lower(regex.replace(path, `^.*/`, ""))

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A condition on the same line, or on a shallower line up to 8 lines above.
# The guard must be a condition (if, elif, a ternary, && or ||): a shallower
# `const debug = require('debug')` decides nothing.
_cond := `\b(if|elif|unless|when)\b|&&|\|\||\?\s*[^.?]`

_guarded(_, _, line, re) if {
	regex.match(re, line)
	regex.match(_cond, line)
}

_guarded(lines, i, line, re) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	l := lines[j]
	not helpers.is_comment_line(l)
	_indent(l) < _indent(line)
	regex.match(re, l)
	regex.match(_cond, l)
}

_py_guard := `\b(DEBUG|debug\w*|environ|getenv|ENV|settings\.\w+)\b`

# ── Python ───────────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "cgitb")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	names := {"cgitb"} | {m[1] | some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+cgitb\s+as\s+(\w+)`, content, -1)}
	some i, line in lines
	contains(line, ".enable(")
	not helpers.is_comment_line(line)
	some n in names
	regex.match(concat("", [`(^|[^\w.])`, n, `\.enable\s*\(`]), line)
	not regex.match(`\bdisplay\s*=\s*(0|False)\b`, line)
	not _guarded(lines, i, line, _py_guard)
	f := _finding(path, i, line, _msg_page)
}

# from cgitb import enable [as name]; enable()
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "cgitb")
	not helpers.is_test_path(path)
	names := {_imported_name(m) | some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+cgitb\s+import\s+enable(?:\s+as\s+(\w+))?`, content, -1)}
	count(names) > 0
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	some n in names
	regex.match(concat("", [`(^|[^\w.])`, n, `\s*\(`]), line)
	not regex.match(`^\s*(def|from|import)\b`, line)
	not regex.match(`\bdisplay\s*=\s*(0|False)\b`, line)
	not _guarded(lines, i, line, _py_guard)
	f := _finding(path, i, line, _msg_page)
}

_imported_name(m) := m[1] if m[1] != ""

_imported_name(m) := "enable" if m[1] == ""

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "SHOW_TOOLBAR_CALLBACK")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SHOW_TOOLBAR_CALLBACK")
	not helpers.is_comment_line(line)
	regex.match(`SHOW_TOOLBAR_CALLBACK["']?\s*[:=]\s*lambda\s*\w*\s*:\s*True\s*[,}]?\s*(#.*)?$`, line)
	f := _finding(path, i, line, _msg_toolbar)
}

# ── Node.js ──────────────────────────────────────────────────────────────

_js_file(path) if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_js_guard := `NODE_ENV|\b(app|server|router)\.get\(\s*["']env["']\s*\)|["']development["']|\b(is)?[dD]ev(elopment|Mode)?\b|\bDEBUG\b|\bdebug\b`

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "errorhandler")
	not helpers.is_test_path(path)
	names := {m[1] | some m in regex.find_all_string_submatch_n(`(?:const|let|var|import)\s+(\w+)\s*(?:=\s*require\(\s*["']errorhandler["']\s*\)|from\s+["']errorhandler["'])`, content, -1)}
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".use(")
	not helpers.is_comment_line(line)
	_mounts_errorhandler(line, names)
	not _js_guarded(lines, i, line)
	f := _finding(path, i, line, _msg_page)
}

# Express 2/3 and connect's own errorHandler, which renders the stack.
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "errorHandler")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "errorHandler")
	not helpers.is_comment_line(line)
	regex.match(`\.use\s*\(\s*(express|connect)\.errorHandler\s*\(\s*(\)|\{[^}]*\b(showStack|dumpExceptions)\s*:\s*true)`, line)
	not _js_guarded(lines, i, line)
	f := _finding(path, i, line, _msg_page)
}

# A check that runs the code only in production is not a development guard,
# unless the line sits in its else branch.
_js_prod_eq := `(NODE_ENV|\.get\(\s*["']env["']\s*\))\s*===?\s*["']prod|["']prod\w*["']\s*===?\s*[\w.]*(NODE_ENV|\.get\(\s*["']env["']\s*\))`

_js_guarded(_, _, line) if {
	regex.match(_js_guard, line)
	regex.match(_cond, line)
	not regex.match(_js_prod_eq, line)
}

_js_guarded(lines, i, line) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	j < i
	l := lines[j]
	not helpers.is_comment_line(l)
	_indent(l) < _indent(line)
	regex.match(_js_guard, l)
	regex.match(_cond, l)
	_js_dev_side(lines, j, i, l)
}

_js_dev_side(_, _, _, l) if not regex.match(_js_prod_eq, l)

_js_dev_side(lines, j, i, l) if {
	regex.match(_js_prod_eq, l)
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^\s*(\}\s*)?else\b`, lines[k])
}

_mounts_errorhandler(line, _) if regex.match(`\.use\s*\(\s*require\(\s*["']errorhandler["']\s*\)\s*\(`, line)

_mounts_errorhandler(line, names) if {
	some n in names
	regex.match(concat("", [`\.use\s*\(\s*`, n, `\s*\(`]), line)
}

_all_ifaces := `(0\.0\.0\.0|\[::\]|::)`

findings contains f if {
	some path, content in input.file_contents
	_inspect_file(path)
	contains(content, "--inspect")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "--inspect")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`--inspect(-brk|-wait)?=["']?`, _all_ifaces, `(:\d+)?\b`]), line)
	f := _finding(path, i, line, _msg_inspect)
}

_inspect_file(path) if _base(path) == "package.json"

_inspect_file(path) if regex.match(`^(dockerfile|containerfile)([._-].*)?$|\.(dockerfile|containerfile)$|^procfile$`, _base(path))

_inspect_file(path) if _ext(lower(path), {".yml", ".yaml", ".sh", ".bash"})

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, "inspector")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "inspector")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\binspector\.open\s*\([^,)]*,\s*["']`, _all_ifaces, `["']`]), line)
	f := _finding(path, i, line, _msg_inspect)
}

# ── ASP.NET Core ─────────────────────────────────────────────────────────

_cs_guard := `IsDevelopment\s*\(|IsEnvironment\s*\(|IsStaging\s*\(|!\s*[\w.]+\.IsProduction\s*\(|EnvironmentName|^\s*#if\s+DEBUG`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"UseDeveloperExceptionPage", "UseDatabaseErrorPage"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"UseDeveloperExceptionPage", "UseDatabaseErrorPage"})
	not helpers.is_comment_line(line)
	regex.match(`\.(UseDeveloperExceptionPage|UseDatabaseErrorPage)\s*\(`, line)
	not _guarded(lines, i, line, _cs_guard)
	not _cs_ifdebug(lines, i)
	f := _finding(path, i, line, _msg_page)
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Inside an #if DEBUG ... #endif block (preprocessor lines sit at any indent).
_cs_ifdebug(lines, i) if {
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`^\s*#if\s+DEBUG\b`, lines[j])
	not _endif_between(lines, j, i)
}

_endif_between(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^\s*#(endif|else)\b`, lines[k])
}
