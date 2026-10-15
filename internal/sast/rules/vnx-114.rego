# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_114

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-114",
	"name": "Process Control: request chooses the library or module loaded",
	"description": "HTTP request data names the native library, plugin or code module the process loads, so a requester can make it load and run code of their choosing (CWE-114 Process Control). Reported sinks: Go plugin.Open; Java System.load/loadLibrary, Runtime.getRuntime().load/loadLibrary and new URLClassLoader; JavaScript/TypeScript require(), dynamic import() and process.dlopen; PHP dl(), FFI::cdef and FFI::load; Python importlib.import_module, __import__, imp.load_source/load_module, importlib.util.spec_from_file_location, and ctypes CDLL/PyDLL/WinDLL/OleDLL and cdll/windll .LoadLibrary; Ruby require, require_relative, load, Fiddle.dlopen and Fiddle::Handle.new. The argument must carry request data (the usual per-language request accessors, or a String Spring handler parameter bound with @RequestParam/@PathVariable/@RequestHeader), inline, concatenated, interpolated, or through a variable assigned from it (or from such a variable) in the 25 lines above. Not reported: constant names, values from configuration, environment or system properties, a request value checked against an allowlist (in / not in, in_array, includes, has, include?, array_key_exists, a switch) or looked up in a map between the read and the load, and calls in comments or string literals. PHP include/require is VNX-98.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-114/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [114],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["process-control", "library-loading", "dynamic-import", "cwe-114"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_src := {
	"go": `\.(?:FormValue|PostFormValue)\s*\(|\.URL\.Query\(\)|\.Header\.Get\s*\(|\bc\.(?:Query|Param|PostForm|DefaultQuery|FormValue|QueryParam)\s*\(|\bmux\.Vars\s*\(`,
	"java": `\.getParameter(?:Values)?\s*\(|\.getHeader\s*\(|@(?:RequestParam|PathVariable|RequestHeader)\b`,
	"php": `\$_(?:GET|POST|REQUEST|COOKIE)\b|php://input|\bfilter_input\s*\(|\$request->(?:input|get|query|post)\s*\(`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|query_params)\b`,
	"rb": `\bparams\b\s*(?:\[|\.(?:fetch|require|permit|dig)\b)|\bcookies\s*\[|\brequest\.(?:body|params|headers)\b`,
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
}

_gate := {
	"go": `plugin\.Open`,
	"java": `\.load(?:Library)?\s*\(|URLClassLoader`,
	"php": `\bdl\s*\(|FFI::`,
	"py": `import_module|__import__|load_source|load_module|spec_from_file_location|DLL\s*\(|LoadLibrary`,
	"rb": `\b(?:require(?:_relative)?|load)\b\s*\(?\s*(?:[^'"\s(]|"[^"]*#\{)|Fiddle`,
	"js": "\\b(?:require|import)\\s*\\(\\s*(?:[^'\"\\s)]|['\"][^'\"]*['\"]\\s*\\+)|dlopen",
}

# The capture is the call's argument text.
_sinks := {
	"go": [`\bplugin\.Open\s*\((.*)$`],
	"java": [
		`\b(?:System|Runtime\.getRuntime\(\))\.load(?:Library)?\s*\((.*)$`,
		`\bnew\s+URLClassLoader\s*\((.*)$`,
	],
	"php": [
		`(?:^|[^\w>$:])dl\s*\((.*)$`,
		`\bFFI::(?:cdef|load)\s*\((.*)$`,
	],
	"py": [
		`\bimportlib\.import_module\s*\((.*)$`,
		`(?:^|[^\w.])import_module\s*\((.*)$`,
		`(?:^|[^\w.])__import__\s*\((.*)$`,
		`\bimp\.load_(?:source|module|dynamic)\s*\((.*)$`,
		`\bspec_from_file_location\s*\((.*)$`,
		`\b(?:ctypes\.)?(?:CDLL|PyDLL|WinDLL|OleDLL)\s*\((.*)$`,
		`\b(?:ctypes\.)?(?:cdll|windll|oledll|pydll)\.LoadLibrary\s*\((.*)$`,
	],
	"rb": [
		`(?:^|[^\w.:])(?:require|require_relative|load)\b\s*\(?(.*)$`,
		`\bFiddle(?:\.dlopen|::Handle\.new)\s*\(?(.*)$`,
	],
	"js": [
		`(?:^|[^\w$.])require\s*\((.*)$`,
		`(?:^|[^\w$.])import\s*\((.*)$`,
		`\bprocess\.dlopen\s*\((.*)$`,
	],
}

_guard := `\bnot\s+in\b|\bin\s+[A-Za-z_][\w.]*\s*:|\bin_array\s*\(|\.includes\s*\(|\.has\s*\(|\.contains(?:Key)?\s*\(|\.include\?\s*\(|\barray_key_exists\s*\(|\bswitch\b|\bcase\b|(?i)allow|whitelist`

_assign_re := `^\s*(?:(?:final|var|let|const|val)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_params(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestHeader)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?String\s+(\w+)`, line, -1)
}

_t1(lang, lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_src[lang], l)
	not helpers.is_comment_line(l)
	v := _assigned(l)
} | {v |
	lang == "java"
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	some v in _params(lines[j])
}

_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_use_re("php", n) := concat("", [`\$`, n, `\b`])

_use_re(lang, n) := concat("", [`\b`, n, `\b`]) if lang != "php"

_guarded(lines, i, lang, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_guard, l)
	regex.match(_use_re(lang, n), l)
	not helpers.is_comment_line(l)
}

# A map lookup keyed by the value (HANDLERS[kind]) picks from fixed entries.
_lookup(lang, arg, n) if regex.match(concat("", [`\w\s*\[\s*`, _use_re(lang, n), `\s*\]`]), arg)

_tainted(lang, lines, i, raw, code) if {
	regex.match(_src[lang], raw)
	not _inline_lookup(lang, raw)
}

# BACKENDS[request.args["b"]] and locales[req.query.lang]: the request value
# only selects one of the program's own entries.
_inline_lookup(lang, raw) if {
	m := regex.find_all_string_submatch_n(`^\s*(\$?[A-Za-z_][\w.]*)\s*\[`, raw, 1)
	count(m) > 0
	not regex.match(_src[lang], concat("", [m[0][1], "["]))
}

_tainted(lang, lines, i, raw, code) if {
	not regex.match(_src[lang], raw)
	n1 := _t1(lang, lines, i)
	some n in n1 | _t2(lines, i, n1)
	regex.match(_use_re(lang, n), code)
	not _lookup(lang, code, n)
	not _guarded(lines, i, lang, n)
}

_code(lang, s) := concat(" ", array.concat([_blank(lang, s)], _interpolated(lang, s)))

_blank("php", s) := regex.replace(s, `'(?:\\.|[^'\\])*'`, `''`)

_blank("py", s) := regex.replace(s, `(?:\b[rbufRBUF]{1,2})?(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`, `""`)

_blank(lang, s) := regex.replace(s, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", `""`) if lang in {"go", "java", "js", "rb"}

_interpolated("php", _) := []

_interpolated("go", _) := []

_interpolated("java", _) := []

_interpolated("js", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, s, -1)]

_interpolated("rb", s) := [m[1] | some m in regex.find_all_string_submatch_n(`#\{([^}]*)\}`, s, -1)]

_interpolated("py", s) := [m[1] | some m in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, s, -1)]

_strip_lits(s) := regex.replace(regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

_args(lines, i, rest) := rest if trim_space(rest) != ""

_args(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_rests(lang, line) := {m[0][1] |
	code := _strip_lits(line)
	some re in _sinks[lang]
	regex.match(re, code)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(lang, content)
	regex.match(_gate[lang], content)
	regex.match(concat("", ["(?m)", _src[lang]]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	some rest in _rests(lang, line)
	arg := _call_args(_args(lines, i, rest))
	_tainted(lang, lines, i, arg, _code(lang, arg))
	finding := {
		"rule_id": metadata.id,
		"message": "Process control: request data chooses the library, plugin or module this process loads, so the requester can make it load and run code of their choosing; map the request value to a fixed set of modules instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The call's own argument list: up to its closing parenthesis, so a chained
# `require('./x').for(name)` is not read as an argument.
_depth(s) := ((strings.count(s, "(") + strings.count(s, "[")) + strings.count(s, "{")) - ((strings.count(s, ")") + strings.count(s, "]")) + strings.count(s, "}"))

_call_args(s) := substring(s, 0, min(ends)) if {
	ends := _close_positions(s)
	count(ends) > 0
}

_call_args(s) := s if count(_close_positions(s)) == 0

_close_positions(s) := [k |
	some k in indexof_n(s, ")")
	_depth(substring(s, 0, k)) == 0
]

# Substring needles: a file that contains none of them cannot match the gate.
_needles := {
	"go": {"plugin.Open"},
	"java": {".load", "URLClassLoader"},
	"php": {"dl(", "dl (", "FFI::"},
	"py": {"import_module", "__import__", "load_source", "load_module", "spec_from_file_location", "DLL(", "LoadLibrary"},
	"rb": {"require", "load", "Fiddle"},
	"js": {"require(", "require (", "import(", "import (", "dlopen"},
}

_has_needle(lang, s) if {
	some n in _needles[lang]
	contains(s, n)
}
