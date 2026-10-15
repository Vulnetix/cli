# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_94

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-94",
	"name": "Code Injection",
	"description": "HTTP request data reaches a dynamic code evaluator, so the requester writes code that the server runs. Reported sinks: JavaScript/TypeScript eval (also window./globalThis./global.eval), new Function / Function, vm.runInNewContext/runInThisContext/runInContext/compileFunction and new vm.Script, and setTimeout/setInterval given a code string; Python eval, exec and compile (bare or builtins.); PHP eval, assert, create_function, and call_user_func/call_user_func_array whose callback is request data; Ruby eval, instance_eval, class_eval and module_eval given a string. Request data is req/request query, body, params, headers or cookies (Koa ctx too), Flask/Django request.args/form/values/json/data/GET/POST/cookies/headers, PHP superglobals, php://input and filter_input, and Rails params/cookies/request.body/request.params, used in the call's argument (including arguments continued on the next two lines) directly or through a variable assigned from it (or from such a variable) in the 25 lines above, including concatenation, template literals, f-strings and PHP/Ruby interpolation. Not reported: evaluators over constants or values never derived from the request, a value passed through a numeric conversion (intval, (int), parseInt, Number, int(), float(), Integer(), to_i) or ast.literal_eval, a variable checked against an allowlist (in_array, array_key_exists, preg_match, includes, has, include?, in CONSTANT, fullmatch/re.match) between the read and the call, setTimeout/setInterval given a function, Ruby eval-family methods given a block, call_user_func with a constant callback, and the names in comments or string literals. Deeper flows (helper functions, collections, other files) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-94/",
	"languages": ["node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["code-injection", "eval", "dynamic-execution", "cwe-94"],
}

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

# Cheap per-file gate: the file names an evaluator at all.
_gate := {
	"js": `eval|Function|vm\.|setTimeout|setInterval`,
	"py": `eval|exec|compile`,
	"php": `eval|assert|create_function|call_user_func`,
	"rb": `eval`,
}

# Request sources per language.
_src := {
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|body|query_params|stream)\b`,
	"php": `\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|php://input|\bfilter_input\s*\(|\$request->(?:input|get|query|post|all)\s*\(`,
	"rb": `\bparams\b\s*(?:\[|\.(?:fetch|require|permit|dig|to_unsafe_h)\b)|\bcookies\s*\[|\brequest\.(?:body|params|query_string|raw_post|headers|cookies|GET|POST)\b`,
}

# A conversion that makes the value inert as code.
_sanitised := `\bintval\s*\(|\(int\)|\bparseInt\s*\(|\bparseFloat\s*\(|\bNumber\s*\(|(?:^|[^\w.])(?:int|float)\s*\(|\bInteger\s*\(|\bFloat\s*\(|\.to_[if]\b|\bliteral_eval\s*\(|\babs\s*\(`

# ── Sinks: the regex is tested on the line with string literals blanked,
# the argument is read from the original line. ──────────────────────────

_sinks := {
	"js": [
		{"gate": `(?:^|[^\w.$])(?:(?:window|globalThis|global)\.)?eval\s*\(`, "arg": `(?:^|[^\w.$])(?:(?:window|globalThis|global)\.)?eval\s*\((.*)$`, "name": "eval"},
		{"gate": `\bnew\s+Function\s*\(|(?:^|[^\w.$])Function\s*\(`, "arg": `\bFunction\s*\((.*)$`, "name": "Function"},
		{"gate": `\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(`, "arg": `\bvm\.\w+\s*\((.*)$`, "name": "vm"},
		{"gate": `\bnew\s+vm\.Script\s*\(`, "arg": `\bvm\.Script\s*\((.*)$`, "name": "vm.Script"},
		{"gate": `(?:^|[^\w.$])set(?:Timeout|Interval)\s*\(`, "arg": `\bset(?:Timeout|Interval)\s*\((.*)$`, "name": "setTimeout"},
	],
	"py": [{"gate": `(?:^|[^\w.]|\bbuiltins\.)(?:eval|exec|compile)\s*\(`, "arg": `(?:^|[^\w.]|\bbuiltins\.)(?:eval|exec|compile)\s*\((.*)$`, "name": "eval"}],
	"php": [
		{"gate": `(?:^|[^\w>$:])(?:eval|assert|create_function)\s*\(`, "arg": `(?:^|[^\w>$:])(?:eval|assert|create_function)\s*\((.*)$`, "name": "eval"},
		{"gate": `(?:^|[^\w>$:])call_user_func(?:_array)?\s*\(`, "arg": `(?:^|[^\w>$:])call_user_func(?:_array)?\s*\(\s*([^,)]*)`, "name": "call_user_func"},
	],
	"rb": [{"gate": `(?:^|[^\w])(?:eval|instance_eval|class_eval|module_eval)\b(?:\s*\(|\s+[^\s{=])`, "arg": `(?:^|[^\w])(?:eval|instance_eval|class_eval|module_eval)\b\s*\(?(.*)$`, "name": "eval"}],
}

_blank(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

# ── One- and two-hop taint ───────────────────────────────────────────────

_assign_re := `^\s*(?:(?:final|var|let|const|val|my|local)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

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

_t1(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(src, l)
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
	v := _assigned(l)
}

_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), _plain_blank(l))
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
}

# Literals that cannot interpolate are blanked for the second hop, so a word
# inside a constant string is not a use of the variable of that name.
# Double-quoted strings holding # or $ (Ruby/PHP interpolation) and f-strings
# are kept.
_plain_blank(l) := regex.replace(l, `(^|[^\w])("(?:\\.|[^"\\#$])*"|'(?:\\.|[^'\\])*')`, `$1""`)

_tainted(lines, i, src, arg) if regex.match(src, arg)

_tainted(lines, i, src, arg) if {
	not regex.match(src, arg)
	n1 := _t1(lines, i, src)
	names := n1 | _t2(lines, i, n1)
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), arg)
	not _guarded(lines, i, n)
}

# An allowlist check on the variable between the read and the call.
_guard_re := `\bin_array\s*\(|\barray_key_exists\s*\(|\bpreg_match\s*\(|\.includes\s*\(|\.include\?\s*\(|\.has\s*\(|\bin\s+[A-Z_][A-Z0-9_]+\b|\bfullmatch\s*\(|\bre\.match\s*\(`

_guarded(lines, i, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_guard_re, l)
	regex.match(concat("", [`\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

# The argument text: the rest of the line, or the next line when the call
# breaks right after its opening parenthesis.
_arg_text(lines, i, rest) := rest if {
	trim_space(rest) != ""
	not _continues(rest)
}

# A call that breaks after an argument separator or operator takes its
# remaining arguments from the next two lines.
_arg_text(lines, i, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, i + 3))) if {
	trim_space(rest) != ""
	_continues(rest)
}

_continues(rest) if regex.match(`[,(+.]\s*$`, rest)

_arg_text(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# A function argument is not code.
_function_arg(arg) if regex.match(`^\s*(?:function\b|async\b|\(|[A-Za-z_$][\w$]*\s*=>)`, arg)

# A Ruby block is not a string.
_block_arg(arg) if regex.match(`^\s*(?:do\b|\{)`, arg)

_skip_arg("js", "setTimeout", arg) if _function_arg(arg)

_skip_arg("rb", _, arg) if _block_arg(arg)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	src := _src[lang]
	regex.match(concat("", ["(?m)", src]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks[lang]
	regex.match(sink.gate, code)
	m := regex.find_all_string_submatch_n(sink.arg, line, 1)
	count(m) > 0
	arg := _arg_text(lines, i, m[0][1])
	not _skip_arg(lang, sink.name, arg)
	not regex.match(_sanitised, arg)
	_tainted(lines, i, src, arg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Code injection: request data reaches %s, which runs it as code; never evaluate request input (use a parser, a dispatch table or a sandboxed expression library)", [sink.name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
