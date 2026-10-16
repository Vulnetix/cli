# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_647

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-647",
	"name": "Authorization decided on a non-canonical request path",
	"description": "An access-control check compares the raw request path or URL with a protected prefix or route, so a different spelling of the same resource (/ADMIN, //admin, /admin;jsessionid=x, /%61dmin, /public/../admin, a query string) slips past the check while the router still serves it (CWE-647). Reported in Java and Kotlin (getRequestURI(), getRequestURL(), getPathInfo(), Kotlin request.requestURI/requestURL/pathInfo), JavaScript/TypeScript (req.path, req.url, req.originalUrl, req.baseUrl, ctx.path/url, Lambda event.path/rawPath) and Python (request.path, path_info, full_path, url, get_full_path(), environ['PATH_INFO'], ASGI scope['path']): a startsWith/startswith/endsWith/equals/includes/contains/indexOf/match/test call, a ==/===/!= comparison or a Python in-tuple test against a literal beginning with '/', or a JavaScript regex literal anchored on '/' (/^\\/admin/.test(...)), applied to that value directly or to a variable assigned from it up to 15 lines above, when the line or the three after it take an access decision (401/403, Forbidden, Unauthorized, sendError, deny, login, auth, role, admin, permission, session, principal, abort). A template file name such as 'admin.html' is not an access decision. Not reported: a path that is normalised first (normalize, normpath, getServletPath, canonical/realpath, cleanPath, safe_join), route registration (app.get('/admin', ...)), path checks with no access decision near them (caching, SPA fallback, health checks), test code, comments and string literals. vnx-551 covers the related order where the check happens before decoding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-647/",
	"languages": ["java", "kotlin", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [647],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["authorization", "canonicalization", "path", "cwe-647"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "java" if endswith(path, ".kt")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_src := {
	"java": `\.getRequestUR[IL]\(\)|\.getPathInfo\(\)|\brequest\.(?:requestURI|requestURL|pathInfo)\b`,
	"js": `\b(?:req|request)\.(?:path|url|originalUrl|baseUrl)\b|\bctx\.(?:path|url|originalUrl)\b|\bevent\.(?:path|rawPath)\b`,
	"py": `\brequest\.(?:path|path_info|full_path|url|base_url|get_full_path\(\))\b|\benviron\[\s*['"]PATH_INFO['"]\s*\]|\bscope\[\s*['"]path['"]\s*\]`,
}

_gate("java", c) if regex.match(`getRequestUR[IL]|getPathInfo|request\.(?:requestUR[IL]|pathInfo)\b`, c)

_gate("js", c) if regex.match(`\b(?:req|request|ctx|event)\.(?:path|url|originalUrl|baseUrl|rawPath)\b`, c)

_gate("py", c) if regex.match(`request\.(?:path|full_path|url|base_url|get_full_path)|PATH_INFO|scope\[`, c)

# A comparison with a literal that begins with "/".
_cmp_re := `\.(?:startsWith|startswith|endsWith|endswith|equals|equalsIgnoreCase|includes|contains|indexOf|match|matches|test)\(\s*\(?\s*[rb]?['"\x60]/|(?:===?|!==?)\s*['"\x60]/|['"\x60]/[^'"\x60]*['"\x60]\s*(?:===?|!==?)|\bin\s*[(\[{]\s*['"]/|/\^?\\/[^/\n]*/[gimsuy]*\.test\(`

_normalised := `(?i)normali[sz]e|normpath|getServletPath|canonical|realpath|cleanPath|clean_path|safe_join`

_decision := `(?i)\b40[13]\b|forbidden|unauthori[sz]ed|sendError|\bden(?:y|ied)\b|log_?in|\bauth\w*|permission|\broles?\b|admin|privilege|\bsession\b|principal|abort\(|has_?perm|is_?staff|is_?superuser|current_user|SC_FORBIDDEN|SC_UNAUTHORIZED`

# String literals with whitespace are prose, not code.
_strip_prose(line) := c if {
	lits := [l |
		some l in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, line, -1)
		regex.match(`\s`, l[0])
	]
	c := strings.replace_n({l[0]: `""` | some l in lits}, line)
}

# Template file names ("dashboard/admin.html") name a view, not a decision.
_strip_templates(s) := regex.replace(s, `["'][^"'\s]*\.(?:html?|jinja2?|j2|tpl|twig|jsp|ftl|mustache|hbs|ejs|pug)["']`, `""`)

# A raw-path variable assigned within 15 lines above i (not normalised).
_raw_vars(lines, i, lang) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	regex.match(_src[lang], prev)
	not regex.match(_normalised, prev)
	not helpers.is_comment_line(prev)
	v := helpers.assigned_first(prev)
}

_raw(_, _, c, lang) if regex.match(_src[lang], c)

_raw(lines, i, c, lang) if {
	some v in _raw_vars(lines, i, lang)
	regex.match(concat("", [`(?:^|[^\w.$])`, v, `\s*(?:\.\w+\(|[=!]=|\bin\b|\))`]), c)
}

_in_docstring(lines, i) if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
	n % 2 == 1
}

_docstring(lines, i, "py") if _in_docstring(lines, i)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_cmp_re, line)
	not helpers.is_comment_line(line)
	c := _strip_prose(line)
	regex.match(_cmp_re, c)
	not regex.match(_normalised, c)
	_raw(lines, i, c, lang)
	regex.match(_decision, _strip_templates(_strip_prose(helpers.code_window(lines, i, 0, 3))))
	not _docstring(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "Access is decided on the raw request path: another spelling of the same resource (//admin, /ADMIN, /admin;x, /%61dmin, /a/../admin) passes the check. Normalise the path first, or enforce access in the router or framework security configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
