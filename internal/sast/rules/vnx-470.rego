# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_470

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-470",
	"name": "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
	"description": "HTTP request data chooses the class, module, method or constant that reflection loads or calls, so a requester can instantiate or invoke code the developer never meant to expose. Reported sinks: Java Class.forName, ClassLoader.loadClass, getMethod/getDeclaredMethod and getField/getDeclaredField; Python importlib.import_module, __import__, getattr (the attribute-name argument), pydoc.locate and globals()[...]; Ruby constantize/safe_constantize (also after classify/camelize), const_get, and send/public_send/__send__ (the method-name argument). The argument must carry request data: inline (request.getParameter/getHeader/getQueryString, request.args/form/values/json/GET/POST/data/headers/cookies, params[...]/request.params/cookies[...]), through a variable assigned from it in the 15 lines above (one further assignment, such as a concatenation or f-string, is followed), a Java handler parameter bound with @RequestParam/@PathVariable/@RequestHeader/@QueryParam/@PathParam/@FormParam, or a Flask/FastAPI handler parameter named by a route placeholder (`/run/<name>`, `/mod/{module}`). Not reported: literal or constant names, a value mapped to constants through a switch/match expression, configuration values, request.method (a fixed set of verbs), a lookup preceded in the 15 lines above by an allow-list test of the same value (ALLOWED.contains(x), x not in ALLOWED, ALLOWED.include?(params[:t]), a matches() pattern), map lookups (PLUGINS[name]), comments and string literals. Overlaps VNX-386 (Java class names built at run time) and VNX-114 (Python module loading from request data).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-470/",
	"languages": ["java", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [470],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["unsafe-reflection", "cwe-470"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "ruby" if endswith(path, ".rb")

_gate := {
	"java": `Class\.forName|loadClass|get(?:Declared)?(?:Method|Field)\s*\(`,
	"python": `import_module|__import__|getattr|pydoc\.locate|globals\s*\(`,
	"ruby": `constantize|const_get|send\s*\(|send_*\s*\(`,
}

# Expressions that read request data, written to capture the whole read.
_source := {
	"java": `\b[A-Za-z_]\w*\.(?:getParameter(?:Values)?|getHeader|getQueryString|getPathInfo|getRequestURI)\s*\([^)]*\)`,
	"python": `\brequest\.(?:args|form|values|json|GET|POST|data|files|headers|cookies|query_params|get_json|match_info|path_params)\b(?:\s*\.\s*get\s*\([^)]*\)|\s*\[[^\]]*\]|\s*\(\s*\))?`,
	"ruby": `\bparams\s*\[[^\]]*\]|\bparams\.(?:fetch|require|dig)\s*\([^)]*\)|\brequest\.(?:params|query_parameters|request_parameters|headers)\b(?:\s*\[[^\]]*\])?|\bcookies\s*\[[^\]]*\]`,
}

# Each sink captures the text that names what is loaded.
_sinks := {
	"java": [
		`\bClass\s*\.\s*forName\s*\((.*)$`,
		`\.\s*loadClass\s*\((.*)$`,
		`\.\s*get(?:Declared)?(?:Method|Field)\s*\(([^,]*)`,
	],
	"python": [
		`\bimport_module\s*\((.*)$`,
		`(?:^|[^\w.])__import__\s*\((.*)$`,
		`\bgetattr\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,([^,]*)`,
		`\bpydoc\.locate\s*\((.*)$`,
		`\bglobals\s*\(\s*\)\s*\[(.*)$`,
	],
	"ruby": [
		`([\w:@\[\]"'.#{}]+?)\.(?:(?:classify|camelize)\.)?(?:safe_)?constantize\b`,
		`\.\s*const_get\s*\(([^,]*)`,
		`\.\s*(?:public_send|__send__|send)\s*\(([^,]*)`,
	],
}

_strip_comment(lang, code) := regex.replace(code, `//.*$`, "") if lang == "java"

_strip_comment(lang, code) := regex.replace(code, `#.*$`, "") if lang == "python"

# Ruby `#{...}` interpolation lives inside a blanked string, so `#` is safe to cut.
_strip_comment(lang, code) := regex.replace(code, `#.*$`, "") if lang == "ruby"

_code(lang, line) := _strip_comment(lang, regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`))

# The argument text: from the raw line (keys and interpolations kept), plus the
# next line when the call opens at the end of this one.
_arg(lines, i, re) := a if {
	m := regex.find_all_string_submatch_n(re, lines[i], 1)
	count(m) > 0
	a := _with_next(lines, i, m[0][1])
}

_with_next(lines, i, a) := concat(" ", [a, lines[i + 1]]) if {
	trim_space(a) == ""
	i + 1 < count(lines)
}

_with_next(_, _, a) := a if trim_space(a) != ""

_annot := `@(?:RequestParam|PathVariable|RequestHeader|QueryParam|PathParam|FormParam|HeaderParam|CookieValue)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w<>\[\],.?]+\s+([A-Za-z_]\w*)`

_bound_params(lang, lines, i) := _java_bound(lines, i) if lang == "java"

_bound_params(lang, lines, i) := _python_bound(lines, i) if lang == "python"

_java_bound(lines, i) := {m[1] |
	some j in numbers.range(max([0, i - 30]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(_annot, lines[j], -1)
}

# Python: a Flask/FastAPI route placeholder (`/run/<name>`, `/mod/{module}`)
# bound to a parameter of the handler the decorator sits on.
_route_re := `^\s*@[A-Za-z_][\w.]*\.(?:route|get|post|put|delete|patch|api_route)\s*\(`

_def_re := `^\s*(?:async\s+)?def\s`

_python_bound(lines, i) := {n |
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(_route_re, lines[j])
	some m in regex.find_all_string_submatch_n(`<(?:\w+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}`, lines[j], -1)
	n := concat("", [m[1], m[2]])
	n != ""
	some k in numbers.range(j + 1, min([j + 5, i - 1]))
	regex.match(_def_re, lines[k])
	regex.match(concat("", [`\(\s*(?:[^)]*[,\s])?`, n, `\b`]), lines[k])
	not _def_between(lines, k + 1, i - 1)
}

_bound_params(lang, _, _) := set() if lang == "ruby"

_def_between(lines, a, b) if {
	a <= b
	some k in numbers.range(a, b)
	regex.match(_def_re, lines[k])
}

_names1(lang, lines, i) := helpers.tainted_names(lines, i, 15, _source[lang]) | _bound_params(lang, lines, i)

# One further assignment: `fqcn = "com.acme." + kind`, `path = f"x.{name}"`.
_names(lang, lines, i) := n1 | {w |
	some j in numbers.range(max([0, i - 15]), i - 1)
	some v in n1
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
	not helpers.is_comment_line(lines[j])
	not regex.match(`=\s*(?:switch|match)\s*\(`, lines[j])
	w := helpers.assigned_first(lines[j])
	w != v
} if {
	n1 := _names1(lang, lines, i)
}

_guard_re := `\.contains(?:Key)?\s*\(|\.include\?|\bnot\s+in\b|\bin\s+[A-Za-z_(\[{]|\.matches\s*\(|\bisValid\w*\s*\(|\bvalidate\w*\s*\(`

_guarded(lines, i, keys) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	regex.match(_guard_re, l)
	not helpers.is_comment_line(l)
	some k in keys
	contains(l, k)
}

_hit(lang, lines, i, arg) if {
	srcs := {s[0] | some s in regex.find_all_string_submatch_n(_source[lang], arg, -1)}
	count(srcs) > 0
	not _guarded(lines, i, srcs)
}

_hit(lang, lines, i, arg) if {
	not regex.match(_source[lang], arg)

	# A name used only as a key into a fixed table (PLUGINS[fmt]) selects
	# from that table, not from anything the requester can name.
	bare := regex.replace(arg, `[A-Za-z_]\w*\s*\[[^\]]*\]|\b[A-Z][A-Z0-9_]*\s*\.\s*(?:get|fetch)\s*\([^)]*\)`, "_")
	used := {v |
		some v in _names(lang, lines, i)
		regex.match(concat("", [`\b`, v, `\b`]), bare)
	}
	count(used) > 0
	not _guarded(lines, i, used)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	some re in _sinks[lang]
	regex.match(re, code)
	arg := _arg(lines, i, re)
	_hit(lang, lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Request data selects the class, module or method that reflection loads or calls (unsafe reflection): a requester can reach code that was never meant to be exposed. Map the input through a fixed allow-list of names to classes instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
