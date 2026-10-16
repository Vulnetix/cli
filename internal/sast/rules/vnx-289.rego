# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_289

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-289",
	"name": "Authentication Bypass by Alternate Name",
	"description": "An access decision compares a name exactly, though the same resource or account can be reached by another spelling of it. Two shapes are reported in Java, JavaScript/TypeScript and Python. A guard on the raw request path: an if that compares Java request.getRequestURI()/getRequestURL(), Node req.url/req.path/req.originalUrl/req.baseUrl or Python request.path/path_info/full_path/url/get_full_path() (inline, through a variable assigned from one in the 10 lines above, or a Node destructuring such as const { path } = req; also when the comparison sits on a continuation line of an if ( opened on the line above) with startsWith/startswith/equals/endsWith/includes/indexOf/==/=== against a '/...' literal, where the literal names a protected area (admin, internal, private, manage, actuator, console, staff, debug...) or the next three lines deny the request (403/401, sendError, abort, HttpResponseForbidden, redirect to login); /ADMIN, //admin, /admin/, /./admin, %61dmin or /admin;x reach the same handler and skip the check. And a reserved-account check: an if comparing a username/login/account name with ==, ===, .equals() or an in-list against admin, administrator, root, superuser, system and similar, or testing membership (in, .has, .includes, .contains) in a collection defined in the file that holds such names (RESERVED = {\"admin\", \"root\"}), followed by a rejection (raise/throw/abort/an error response) within three lines, without case folding; 'Admin' or 'ROOT' passes. Not reported: a path or name that is lower-cased, normalised or decoded first, on the line or where it was assigned (toLowerCase, lower(), casefold, normalize, decodeURI, unquote, equalsIgnoreCase), an exemption whose body only passes the request on (return next(), chain.doFilter, get_response), which fails closed, Java getServletPath(), comparisons against unprotected paths that do not deny (routing such as req.url === '/health'), role checks (user.role == 'admin'), and comments or string literals. Whether the framework itself normalises the path before this code runs is configuration and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-289/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [289],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["auth-bypass-alternate-name", "path-normalisation", "cwe-289"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

_path_src := {
	"java": `\.getRequestUR[IL]\(\)`,
	"js": `\b(req|request)\.(url|path|originalUrl|baseUrl)\b`,
	"py": `\brequest\.(path|path_info|full_path|url|get_full_path\(\))(\b|$)`,
}

_needle := {"java": "getRequestUR", "js": "req", "py": "request."}

_folded := `(?i)toLowerCase|toUpperCase|lower\(|upper\(|casefold|normali[sz]e|decodeURI|unquote|IgnoreCase|realpath|resolve\(`

_if_re := `^\s*(\}?\s*else\s+)?(if|elif)\b|\bif\s*\(`

_cmp_re := `\.(startsWith|startswith|equals|endsWith|endswith|includes|indexOf|contains|matches)\s*\(|===?|!==?|\s(not\s+)?in\s`

_protected := `(?i)^/+(api/(v\d+/)?)?(admin|administrator|internal|private|manage|management|manager|actuator|console|secure|staff|debug|ops|system|superuser|root|wp-admin|phpmyadmin|jmx|h2-console)\b`

_deny := `(?i)sendError|SC_FORBIDDEN|SC_UNAUTHORIZED|status\(\s*40[13]|sendStatus\(\s*40[13]|statusCode\s*=\s*40[13]|HttpResponseForbidden|HttpResponseRedirect\([^)]*login|abort\(\s*40[13]|PermissionDenied|Forbidden|Unauthorized|redirect\([^)]*login|AccessDenied`

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `"s"`), `'(\\.|[^'\\])*'`, `'s'`)

_literals(line) := [m[1] | some m in regex.find_all_string_submatch_n(`["'](/[^"']*)["']`, line, -1)]

_denies(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 3]))
	not helpers.is_comment_line(lines[k])
	regex.match(_deny, lines[k])
}

# The line reads the raw path, inline or through a variable assigned from it.
_reads_path(lines, i, lang, line) if regex.match(_path_src[lang], line)

_reads_path(lines, i, lang, line) if {
	some v in helpers.tainted_names(lines, i, 10, _path_src[lang])
	regex.match(concat("", [`\b`, v, `\b`]), line)
	not _assigned_folded(lines, i, v)
}

# Node destructuring: `const { path } = req;`, `const { originalUrl: u } = req;`.
_reads_path(lines, i, "js", line) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[j], "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\s*;?\s*$`, lines[j], 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	kv := split(trim_space(part), ":")
	trim_space(kv[0]) in {"url", "path", "originalUrl", "baseUrl"}
	v := trim_space(kv[count(kv) - 1])
	regex.match(concat("", [`\b`, v, `\.(startsWith|endsWith|includes|indexOf|match)\(|\b`, v, `\s*[!=]==?`]), line)
}

_reads_path_somewhere(lang, content) if regex.match(_path_src[lang], content)

_reads_path_somewhere("js", content) if regex.match(`\}\s*=\s*(req|request)\s*;?\s*(\n|$)`, content)

# The condition of an `if (` opened on one of the two lines above.
_in_if(lines, i, line) if regex.match(_if_re, line)

_in_if(lines, i, line) if {
	some k in [i - 1, i - 2]
	k >= 0
	regex.match(`\bif\s*\(\s*$`, lines[k])
	not _brace_between(lines, k, i)
}

_brace_between(lines, k, i) if {
	some b in helpers.span(k + 1, i - 1)
	b < i
	contains(lines[b], "{")
}

# An exemption: the matched path skips the check (`return next()`,
# chain.doFilter). An exact match there fails closed, so it is not a bypass.
_pass_re := `^\s*(return\s+)?(next\(\)|\w*[cC]hain\.doFilter\(|(self\.)?get_response\()`

_exempts(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\)\s*\{?\s*(.*)$`, line, -1)
	count(m) > 0
	regex.match(_pass_re, m[count(m) - 1][1])
}

_exempts(lines, i, line) if {
	regex.match(`[\{:]\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(_pass_re, lines[j])
}

# The variable's own assignment folds or normalises the path.
_assigned_folded(lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	helpers.assigned_first(lines[j]) == v
	regex.match(_folded, lines[j])
}

_path_guard(lines, i, lang, line) if {
	_in_if(lines, i, line)
	regex.match(_cmp_re, _code(line))
	lits := _literals(line)
	count(lits) > 0
	not regex.match(_folded, line)
	_reads_path(lines, i, lang, line)
	_protected_or_denied(lines, i, lits)
}

_protected_or_denied(lines, i, lits) if {
	some l in lits
	regex.match(_protected, l)
}

_protected_or_denied(lines, i, _) if _denies(lines, i)

# Reserved account names compared case-sensitively.
_reserved := `(admin|administrator|root|superuser|super_user|sysadmin|system|support|postmaster|webmaster|hostmaster)`

_reserved_lit := concat("", [`["']`, _reserved, `["']`])

_ident := `(?i)\b(\w*user_?name|\w*login(_?name)?|\w*account_?name|user|uname|nick(_?name)?|handle)`

_name_cmp_res := [
	concat("", [_ident, `\s*(===?|\.equals\()\s*["']`, _reserved, `["']`]),
	concat("", [`["']`, _reserved, `["']\s*(===?|\.equals\()\s*`, _ident, `\b`]),
	concat("", [_ident, `\s+in\s+[\(\[\{][^)\]\}]*["']`, _reserved, `["']`]),
]

_reject := `(?i)\braise\b|\bthrow\b|\babort\(|reserved|not allowed|forbidden|denied|status\(\s*4\d\d|sendError|,\s*4\d\d\s*$|return\s+(false|False|None)\b|HttpResponse(Forbidden|BadRequest)|ValidationError`

_rejects(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 3]))
	not helpers.is_comment_line(lines[k])
	regex.match(_reject, lines[k])
}

_name_guard(lines, i, line, _) if {
	regex.match(_if_re, line)
	some re in _name_cmp_res
	regex.match(re, line)
	not regex.match(_folded, line)
	not _name_folded_above(lines, i, line)
	_rejects(lines, i)
}

# Membership in a named collection of reserved names defined in the file:
# `RESERVED = {"admin", "root"}` ... `if name in RESERVED:` / RESERVED.has(name).
_name_guard(lines, i, line, sets) if {
	regex.match(_if_re, line)
	some s in sets
	contains(line, s)
	m := _set_member(line, s)
	not regex.match(_folded, line)
	not _name_folded_above(lines, i, line)
	_set_or_ident_reserved(s, m)
	_rejects(lines, i)
}

_set_member(line, s) := mm[0][1] if {
	mm := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_][\w.]*)\s+in\s+`, s, `\b`]), line, 1)
	count(mm) > 0
} else := mm[0][1] if {
	mm := regex.find_all_string_submatch_n(concat("", [`\b`, s, `\.(?:has|includes|contains)\(\s*([A-Za-z_][\w.]*)\s*\)`]), line, 1)
	count(mm) > 0
}

_set_or_ident_reserved(s, _) if regex.match(`(?i)reserved|block|banned|forbidden|blacklist|denylist|disallow|restricted|protected`, s)

_set_or_ident_reserved(_, m) if regex.match(concat("", [_ident, `$`]), m)

# Names bound to a collection literal that holds a reserved account name.
_reserved_sets(lines) := {m[0][1] |
	some j, l in lines
	contains(l, "=")
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:private|public|protected|static|final|readonly|export|const|let|var)\s+)*(?:[\w<>,\s]+?\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:new\s+(?:Hash)?Set\s*(?:<[^>]*>)?\(|Set\.of\(|List\.of\(|Arrays\.asList\(|frozenset\(|set\(|tuple\(|[\[\{\(])`, l, 1)
	count(m) > 0
	regex.match(_reserved_lit, concat(" ", array.slice(lines, j, min([count(lines), j + 6]))))
}

# The compared name was case-folded or normalised when it was assigned.
_name_folded_above(lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(_folded, lines[j])
	v := helpers.assigned_first(lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _needle[lang])
	_reads_path_somewhere(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "/")
	not helpers.is_comment_line(line)
	_path_guard(lines, i, lang, line)
	not _exempts(lines, i, line)
	finding := _finding(path, i, line, "This access check compares the raw request path exactly, but the same handler is reachable by another spelling of it (/ADMIN, //admin, /admin/, /./admin, %61dmin, /admin;x), so the check is skipped. Enforce access in the router or security framework on the matched route, or normalise, decode and lower-case the path before comparing")
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(_reserved_lit, content)
	lines := split(content, "\n")
	sets := _reserved_sets(lines)
	some i, line in lines
	contains(line, "if")
	not helpers.is_comment_line(line)
	_name_guard(lines, i, line, sets)
	finding := _finding(path, i, line, "A reserved account name is rejected by an exact, case-sensitive comparison, so 'Admin', 'ROOT' or a Unicode lookalike passes and can be registered or used as the privileged account. Compare a canonical form (casefold/lower-case after Unicode normalisation) against the reserved set")
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
