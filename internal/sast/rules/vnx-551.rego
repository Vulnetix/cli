# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_551

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-551",
	"name": "Incorrect Behavior Order: Authorization Before Parsing and Canonicalization",
	"description": "An access decision is taken on a request-supplied path or resource name, and the same value is only decoded, parsed or canonicalised afterwards, so the check judged a different string from the one the code goes on to use (/%61dmin, /a/../admin and /admin;x pass a check on the raw text and then become /admin). Reported in Java, Python and JavaScript/TypeScript: a condition that compares a request-derived variable with startsWith/startswith/endsWith/equals/includes/indexOf/==/=== against a '/...' literal (either side, as in \"/login\".equals(uri)), or passes it to an authorisation call (authorize, checkPermission, hasPermission, hasAccess, canAccess, checkAccess, isAllowed, isPermitted, isAuthorized, requirePermission, enforce), when one of the next 15 lines passes that same variable to URLDecoder.decode, decodeURI/decodeURIComponent, unquote/unquote_plus, normpath/realpath/abspath, getCanonicalPath, Paths.get/Path.of, normalize, path.normalize/path.resolve, urlparse/urlsplit, url.parse, new URL/new URI or URI.create. The subject is the request path read inline (req.path, req.url, req.originalUrl, request.path, request.path_info), or a variable (including a TypeScript annotated declaration) assigned from the request (getRequestURI, getPathInfo, getServletPath, getParameter, getHeader, getQueryString; request.path/args/form/GET/full_path; req.url/path/originalUrl/params/query/body) in the 20 lines above. Not reported: a value decoded or canonicalised before it is checked, a check on one variable followed by decoding a different one, values that do not come from the request, comments and string literals. Checks for dangerous sequences followed by decoding are VNX-179; guards on the raw request path regardless of later decoding are VNX-289; directory-containment checks on non-canonical paths are VNX-41.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-551/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [551],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["authz-before-canonicalization", "cwe-551"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

_src := {
	"java": `\.(getRequestUR[IL]|getPathInfo|getServletPath|getParameter|getHeader|getQueryString)\(`,
	"py": `\brequest\.(path|path_info|full_path|get_full_path|url|args|form|values|GET|POST|query_params|match_info|view_args)\b`,
	"js": `\b(req|request|ctx)\.(url|path|originalUrl|baseUrl|params|query|body)\b`,
}

_needle := {"java": "Request", "py": "request.", "js": "req"}

_canon_fn := `(?:URLDecoder\.decode|decodeURIComponent|decodeURI|unquote(?:_plus)?|url2pathname|normpath|realpath|abspath|(?:Normalizer|path|posix|posixpath|unicodedata)\.normalize|path\.resolve|getCanonicalPath|getCanonicalFile|urlparse|urlsplit|url\.parse|new\s+URL|new\s+URI|URI\.create|Paths\.get|Path\.of|querystring\.unescape)`

# Whole-file gate: something that decodes or canonicalises.
_gate := `URLDecoder|decodeURI|unquote|normpath|realpath|abspath|normalize|getCanonical|urlparse|urlsplit|url\.parse|new URL|new URI|URI\.create|Paths\.get|Path\.of|path\.resolve`

_authz_fn := `(?i)\b(?:is_?authori[sz]ed|authori[sz]e|check_?permissions?|has_?permissions?|has_?access|can_?access|check_?access|is_?allowed|is_?permitted|require_?permissions?|check_?authori[sz]ation|enforce)\s*\(`

# A comparison of the subject against a path literal, in a condition.
_cmp_re(v) := concat("", [
	`\b`, v, `\s*(?:\.\s*(?:startsWith|startswith|endsWith|endswith|equals|includes|indexOf|contains|matches)\s*\(\s*|===?\s*|!==?\s*)["']/`,
])

# A literal compared with the subject: "/login".equals(uri).
_rcmp_re(v) := concat("", [
	`["']/[^"']*["']\s*\.\s*(?:equals|equalsIgnoreCase|startsWith|endsWith)\s*\(\s*`, v, `\s*\)`,
])

# Request-derived names, including TypeScript annotated declarations
# (const p: string = req.path).
_tainted(lines, i, lang) := helpers.tainted_names(lines, i, 20, _src[lang]) | {v |
	lang == "js"
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(_src[lang], lines[j])
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:[^=]+=[^=]`, lines[j], 1)
	count(m) > 0
	v := m[0][1]
}

# The request path read inline, without a variable: if (req.path.startsWith(...)).
# Returned regex-escaped, ready to splice into the patterns below.
_inline_re := {
	"js": `\b(?:req|request|ctx)\.(?:path|url|originalUrl|baseUrl)\b`,
	"py": `\brequest\.(?:path|path_info|full_path)\b`,
}

_inline(line, lang) := {replace(m, ".", `\.`) |
	some m in regex.find_n(_inline_re[lang], line, -1)
}

_subjects(lines, i, line, lang) := _tainted(lines, i, lang) | _inline(line, lang) if lang != "java"

_subjects(lines, i, _, "java") := _tainted(lines, i, "java")

_cond_re := `^\s*(\}?\s*else\s+)?(if|elif|unless|while)\b|\bif\s*\(|^\s*return\b|\?\s*$`

_strip(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The authorisation call names the subject, on this line or the next two
# (a call broken across lines).
_authz_names(lines, i, v) if {
	regex.match(_authz_fn, lines[i])
	txt := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 2]))])
	regex.match(concat("", [_authz_fn, `[^;]*\b`, v, `\b`]), txt)
}

_candidate(line) if {
	contains(line, "/")
	regex.match(`["']/`, line)
	regex.match(`startsWith|startswith|endsWith|endswith|equals|includes|indexOf|contains|matches|==`, line)
}

_candidate(line) if {
	contains(line, "(")
	regex.match(_authz_fn, line)
}

_checks(lines, i, line, v) if {
	regex.match(_cond_re, _strip(line))
	regex.match(_cmp_re(v), line)
}

_checks(lines, i, line, v) if {
	regex.match(_cond_re, _strip(line))
	regex.match(_rcmp_re(v), line)
}

_checks(lines, i, _, v) if _authz_names(lines, i, v)

# The subject is decoded or canonicalised on line j.
_canonicalises(line, v) if {
	regex.match(concat("", [_canon_fn, `\s*\([^;]*\b`, v, `\b`]), _strip(line))
}

_canonicalises(line, v) if {
	regex.match(concat("", [`new\s+(?:[\w.]+\.)?File\s*\([^;]*\b`, v, `\b[^;]*\)\s*\.\s*getCanonical`]), line)
}

_canonicalises(line, v) if {
	regex.match(concat("", [`\b`, v, `\s*\.\s*(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile)\s*\(`]), line)
}

# The subject was itself assigned from a decode or canonicalisation.
_assigned_canon(lines, i, v) if {
	some j in numbers.range(max([0, i - 20]), i - 1)
	helpers.assigned_first(lines[j]) == v
	regex.match(_canon_fn, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _needle[lang])
	regex.match(_gate, content)
	regex.match(_src[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_candidate(line)
	not helpers.is_comment_line(line)
	regex.match(_canon_fn, concat("\n", array.slice(lines, i + 1, i + 16)))
	some v in _subjects(lines, i, line, lang)
	not _assigned_canon(lines, i, v)
	_checks(lines, i, line, v)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	not helpers.is_comment_line(lines[j])
	_canonicalises(lines[j], v)
	finding := {
		"rule_id": metadata.id,
		"message": "Access decision taken on a request value that is only decoded or canonicalised afterwards; decode and canonicalise first, then authorise the canonical form",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
