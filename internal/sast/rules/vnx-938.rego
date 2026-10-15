# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_938

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-938",
	"name": "Unvalidated redirect or forward to a request-supplied destination",
	"description": "CWE-938 is the OWASP Top Ten 2013 category 'Unvalidated Redirects and Forwards'. This rule reports the two concrete shapes not covered by the per-language open-redirect rules: in Python (Flask, Django, Starlette/FastAPI), redirect(), HttpResponseRedirect(), HttpResponsePermanentRedirect() or RedirectResponse() whose destination is request data (request.args/form/values/GET/POST/REQUEST/query_params/cookies/headers/referrer/json/get_json()/META), read inline or through up to two assignments in the 20 lines above; and in Java and Kotlin, a server-side forward to a request-supplied path: getRequestDispatcher()/getNamedDispatcher() or a Spring \"forward:\" view name built from request.getParameter/getHeader/getQueryString/getCookies or from a @RequestParam/@PathVariable/@RequestHeader/@CookieValue parameter, plus, in Kotlin only (VNX-JAVA-007 covers Java), sendRedirect() and \"redirect:\" view names built the same way. A forward runs inside the application, so a user-chosen path can reach pages the user's role should not (a fixed prefix such as \"/WEB-INF/views/\" + page does not prevent ../ traversal). Not reported: a destination that starts with a fixed literal (redirect(f\"/blog/{id}\"), \"/docs/\" + page, a Kotlin \"redirect:/home?tab=$tab\"; a forward: keeps being reported), url_for/reverse lookups and named URL patterns, a value looked up in a constant map, a value checked between the read and the sink or in an if just above it (url_has_allowed_host_and_scheme, is_safe_url, urlparse/netloc, startswith, an allowlist membership or containsKey/equals/matches test), request attributes and other server-side values, comments and string literals. Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-938/",
	"languages": ["python", "java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [938],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "forward", "cwe-938"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "kt" if endswith(path, ".kt")

# ── Sources, sinks and guards per language ─────────────────────────────────

_src("py") := `\brequest\.(?:(?:args|form|values|GET|POST|REQUEST|query_params|cookies|headers|referrer|json|META)\b|get_json\()`

_jvm_src := `\.(getParameter|getParameterValues|getHeader|getQueryString|getCookies)\s*\(`

_src("java") := _jvm_src

_src("kt") := _jvm_src

_sinks("py") := [`\b(?:redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\((.*)$`]

_sinks("java") := [`\b(?:getRequestDispatcher|getNamedDispatcher)\s*\((.*)$`, `"forward:(.*)$`]

_sinks("kt") := [
	`\b(?:getRequestDispatcher|getNamedDispatcher)\s*\((.*)$`,
	`"forward:(.*)$`,
	`\.sendRedirect\s*\((.*)$`,
	`"redirect:(.*)$`,
]

_file_gate("py") := `(redirect|Redirect|RedirectResponse)\s*\(`

_file_gate("java") := `getRequestDispatcher|getNamedDispatcher|"forward:`

_file_gate("kt") := `getRequestDispatcher|getNamedDispatcher|"forward:|sendRedirect|"redirect:`

_guard("py") := `url_has_allowed_host_and_scheme|is_safe_url|urlparse|urlsplit|netloc|\.startswith\(|\bnot\s+in\b|\bin\s+[A-Za-z_][\w.]*\s*:|(?i)allow|whitelist|safe_|_safe|valid|trusted`

_jvm_guard := `containsKey\(|\.contains\(|startsWith\(|\.matches\(|\.equals\(|equalsIgnoreCase\(|(?i)isAllowed|isValid|isSafe|allowlist|whitelist|allowed|switch\s*\(|when\s*\(`

_guard("java") := _jvm_guard

_guard("kt") := _jvm_guard

# A destination taken from a constant map is chosen by the application.
_lookup := `(^|[^.\w])[A-Z][A-Z0-9_]+\s*\.\s*(get|getOrDefault)\s*\(|\.getOrDefault\s*\(`

_spring_param_java := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b(?:\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\]]+\s+(\w+)`

_spring_param_kt := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b(?:\([^)]*\))?\s+(\w+)\s*:`

_strip_strings(line) := regex.replace(line, `"([^"\\]|\\.)*"|'([^'\\]|\\.)*'`, `""`)

_word(v) := concat("", [`\b`, v, `\b`])

# ── Arguments of the sink ─────────────────────────────────────────────────

_sink_args(lang, line) := a if {
	some re in _sinks(lang)
	_sink_in_code(lang, re, line)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	a := m[0][1]
}

# The call must be in code, not inside a string literal. The forward:/redirect:
# sinks are themselves string literals and are tested on the raw line.
_sink_in_code(_, re, _) if startswith(re, `"`)

_sink_in_code(_, re, line) if {
	not startswith(re, `"`)
	regex.match(re, _strip_strings(line))
}

_args(lang, lines, i, line) := a if {
	a0 := _sink_args(lang, line)
	not regex.match(`^\s*$`, a0)
	a := a0
}

_args(lang, lines, i, line) := a if {
	regex.match(`^\s*$`, _sink_args(lang, line))
	a := concat(" ", [lines[k] | some k in numbers.range(i + 1, min([i + 2, count(lines) - 1]))])
}

# A destination with a fixed leading literal, or a route-name lookup.
_fixed("py", args) if regex.match(`^\s*[fFrRuUbB]?["'][^"'{]`, args)

_fixed("py", args) if regex.match(`^\s*(url_for|reverse|resolve_url|reverse_lazy)\s*\(`, args)

_fixed("py", args) if regex.match(`^\s*["'][^"']*["']\s*,`, args)

_fixed(_, args) if regex.match(_lookup, args)

# A Kotlin "redirect:" view name whose literal names a fixed local path or
# host before any interpolation ("redirect:/home?tab=$tab"). A forward: is
# not exempt: a fixed prefix does not stop ../ traversal inside the app.
_fixed_redirect_literal("kt", line) if regex.match(`"redirect:(/[^/"$\\]|https?://[^"$/]+/)`, line)

# ── Taint ─────────────────────────────────────────────────────────────────

_hop1(lang, lines, i) := {[j, v] |
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src(lang), l)
	not regex.match(_lookup, l)
	v := helpers.assigned_first(l)
}

_hop2(lines, i, h1) := {[j0, w] |
	some [j0, v] in h1
	j0 + 1 <= i - 1
	some k in numbers.range(j0 + 1, i - 1)
	l := lines[k]
	regex.match(_word(v), l)
	not helpers.is_comment_line(l)
	not regex.match(_lookup, l)
	w := helpers.assigned_first(l)
	w != v
}

_params("java", lines, i) := {[j, v] |
	some j in numbers.range(max([0, i - 15]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(_spring_param_java, lines[j], -1)
	v := m[1]
}

_params("kt", lines, i) := {[j, v] |
	some j in numbers.range(max([0, i - 15]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(_spring_param_kt, lines[j], -1)
	v := m[1]
}

_params("py", _, _) := set()

_guarded(lang, lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_guard(lang), l)
}

_guarded_inline(lang, lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*(\}\s*)?(if|elif|else\s+if)\b`, lines[k])
	regex.match(_guard(lang), lines[k])
}

_reaches(lang, lines, i, args) if {
	regex.match(_src(lang), args)
	not _guarded_inline(lang, lines, i)
}

_reaches(lang, lines, i, args) if {
	h1 := _hop1(lang, lines, i) | _params(lang, lines, i)
	some [j, v] in h1 | _hop2(lines, i, h1)
	regex.match(_word(v), args)
	not _guarded(lang, lines, j, i)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_file_gate(lang), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_file_gate(lang), line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*def\s`, line)
	args := _args(lang, lines, i, line)
	not _fixed(lang, args)
	not _fixed_redirect_literal(lang, line)
	_reaches(lang, lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect or forward destination comes from the request without validation: an attacker chooses where the user is sent (or which internal page is served). Map the value to a fixed set of destinations, or check it against an allowlist first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
