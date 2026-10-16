# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_913

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-913",
	"name": "Request data chooses the file of code the process loads or runs (improper control of dynamically-managed code resources)",
	"description": "HTTP request data names the FILE of code or native code that the process loads or executes, so a requester can run a script, plugin or library of their choosing (CWE-913). Reported sinks: Java ScriptEngine/Rhino `.eval(new FileReader(path))` (also InputStreamReader, FileInputStream, Files.newBufferedReader), GroovyShell evaluate/parse/run with a File, GroovyClassLoader.parseClass, URLClassLoader.newInstance, and JNA Native.load/loadLibrary and NativeLibrary.getInstance; Python runpy.run_path/run_module, importlib.machinery SourceFileLoader/SourcelessFileLoader/ExtensionFileLoader, imp.load_compiled, execfile, zipimporter and cffi ffi.dlopen; Node.js `new Worker(path)` from worker_threads, Module._load, new vm.SourceTextModule, vm2 runFile, and koffi.load / ffi.Library; Go syscall and golang.org/x/sys/windows LoadDLL/NewLazyDLL/LoadLibrary, purego.Dlopen, gopher-lua DoFile and yaegi EvalPath. The path argument must carry request data: inline (request.getParameter/getHeader, @RequestParam/@PathVariable bound String parameters, request.args/form/values/json/GET/POST/view_args, req/request query/body/params/headers/cookies, ctx.query/ctx.params, r.FormValue/PathValue/URL.Query/Header.Get, c.Query/Param, mux.Vars), concatenated or interpolated, or through a variable assigned or destructured from it (or from such a variable) in the 25 lines above. Not reported: constant paths, values from configuration or the environment, a path wrapped in basename/secure_filename/filepath.Base/getFileName, a value checked against an allowlist, a numeric conversion, or confined by a prefix check (startsWith/startswith/HasPrefix/commonpath/is_relative_to) between the read and the load, and names in comments or string literals. Not reported here because another rule owns them: eval/exec/Function/vm over a code string or file contents read from a request path (VNX-94), System.load/loadLibrary, URLClassLoader constructor, plugin.Open, ctypes CDLL/LoadLibrary, import_module, require()/import()/process.dlopen and Ruby require/load (VNX-114, VNX-1027), reflection that picks a class, module or method (VNX-470), PHP include/require (VNX-98) and mass assignment (VNX-915).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-913/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [913],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["dynamic-code", "code-loading", "path-control", "cwe-913"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_src := {
	"java": `\.getParameter(?:Values)?\s*\(|\.getHeader\s*\(|\.getPathInfo\s*\(|\.getQueryString\s*\(|\.getRequestURI\s*\(|@(?:RequestParam|PathVariable|RequestHeader|QueryParam|PathParam|FormParam)\b`,
	"py": `\brequest\.(?:args|form|values|json|get_json|data|cookies|headers|GET|POST|query_params|view_args|files)\b`,
	"js": `\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body|request\.query)\b`,
	"go": `\.(?:FormValue|PostFormValue|PathValue)\s*\(|\.URL\.(?:Query\(\)|Path)|\.Header\.Get\s*\(|\bc\.(?:Query|Param|PostForm|DefaultQuery|FormValue|QueryParam|GetHeader)\s*\(|\bmux\.Vars\s*\(|\bchi\.URLParam\s*\(`,
}

# Cheap per-file gate: the file names one of the loaders at all.
_gate := {
	"java": `\.eval\s*\(|evaluate|\.parse\s*\(|\.run\s*\(|parseClass|newInstance|Native|loadLibrary`,
	"py": `run_path|run_module|FileLoader|load_compiled|execfile|zipimporter|dlopen`,
	"js": `Worker|_load|SourceTextModule|runFile|koffi|ffi`,
	"go": `LoadDLL|NewLazy|LoadLibrary|Dlopen|DoFile|EvalPath`,
}

# Each sink: re is tested on the line with literals blanked and captures the
# argument text; ctx (optional) must appear in the file, for sinks whose method
# name alone is too common.
_sinks := {
	"java": [
		{"re": `\.\s*eval\s*\(\s*(?:new\s+(?:[\w.]+\.)?(?:FileReader|InputStreamReader|FileInputStream|BufferedReader)\b|(?:Files\s*\.\s*)?newBufferedReader\b)(.*)$`, "ctx": ""},
		{"re": `\b\w*(?:[Ss]hell|[Ee]ngine|[Ss]cript\w*)\s*\.\s*(?:evaluate|parse|run)\s*\(\s*new\s+File\s*\((.*)$`, "ctx": ""},
		{"re": `\.\s*parseClass\s*\((.*)$`, "ctx": "Groovy"},
		{"re": `\bURLClassLoader\s*\.\s*newInstance\s*\((.*)$`, "ctx": ""},
		{"re": `\bNative\s*\.\s*load(?:Library)?\s*\((.*)$`, "ctx": "jna"},
		{"re": `\bNativeLibrary\s*\.\s*getInstance\s*\((.*)$`, "ctx": ""},
	],
	"py": [
		{"re": `(?:^|[^\w.])(?:runpy\.)?run_(?:path|module)\s*\((.*)$`, "ctx": "runpy"},
		{"re": `\b(?:Source|Sourceless|Extension)FileLoader\s*\((.*)$`, "ctx": ""},
		{"re": `\bimp\.load_compiled\s*\((.*)$`, "ctx": ""},
		{"re": `(?:^|[^\w.])execfile\s*\((.*)$`, "ctx": ""},
		{"re": `\bzipimporter\s*\((.*)$`, "ctx": ""},
		{"re": `\bffi\.dlopen\s*\((.*)$`, "ctx": ""},
	],
	"js": [
		{"re": `\bnew\s+Worker\s*\((.*)$`, "ctx": "worker_threads"},
		{"re": `\bModule\s*\.\s*_load\s*\((.*)$`, "ctx": ""},
		{"re": `\bnew\s+(?:vm\.)?SourceTextModule\s*\((.*)$`, "ctx": ""},
		{"re": `\.\s*runFile\s*\((.*)$`, "ctx": "vm2"},
		{"re": `\bkoffi\.load\s*\((.*)$`, "ctx": ""},
		{"re": `\bffi\.(?:Library|DynamicLibrary)\s*\((.*)$`, "ctx": ""},
	],
	"go": [
		{"re": `\b(?:syscall|windows)\.(?:LoadDLL|NewLazyDLL|LoadLibrary|NewLazySystemDLL)\s*\((.*)$`, "ctx": ""},
		{"re": `\bpurego\.Dlopen\s*\((.*)$`, "ctx": ""},
		{"re": `\.\s*DoFile\s*\((.*)$`, "ctx": "lua"},
		{"re": `\.\s*EvalPath\s*\((.*)$`, "ctx": "yaegi"},
	],
}

# A conversion that leaves nothing but a number.
_sanitised := `\bintval\s*\(|\bparseInt\s*\(|\bNumber\s*\(|(?:^|[^\w.])(?:int|float)\s*\(|\bInteger\.parseInt\s*\(|\bLong\.parseLong\s*\(|\bstrconv\.(?:Atoi|ParseInt)\s*\(`

# The path is reduced to its last element, or to a file-name the framework made safe.
_wrapped := `\bbasename\s*\(|\bsecure_filename\s*\(|\bfilepath\.Base\s*\(|\.getFileName\s*\(|\bpath\.basename\s*\(`

# An allowlist, a pattern check or a prefix confinement on the value.
_guard_re := `\bnot\s+in\b|\bin\s+[A-Za-z_][\w.]*\s*:|\.includes\s*\(|\.has\s*\(|\.contains(?:Key)?\s*\(|\.matches\s*\(|\bfullmatch\s*\(|\bre\.match\s*\(|\bstartsWith\s*\(|\bstartswith\s*\(|\bHasPrefix\s*\(|\bcommonpath\s*\(|\bis_relative_to\s*\(|\bisRelativeTo\s*\(|\bswitch\b|(?i)allow|whitelist`

_destructured(line) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	pieces := split(trim_space(part), ":")
	v := trim_space(pieces[count(pieces) - 1])
	regex.match(`^[A-Za-z_]\w*$`, v)
}

_assigned(line) := {v | v := helpers.assigned_first(line)} | _destructured(line)

_params(lang, lines, i) := {m[1] |
	lang == "java"
	some j in helpers.span(max([0, i - 30]), i)
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestHeader|QueryParam|PathParam|FormParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?String\s+(\w+)`, lines[j], -1)
}

_t1(lang, lines, i) := {v |
	some j in helpers.span(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_src[lang], l)
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
	some v in _assigned(l)
} | _params(lang, lines, i)

# Literals that cannot interpolate are blanked, so a word inside a constant
# string is not a use of the variable of that name. f-strings, template
# literals and double-quoted strings holding $ or # are kept.
_plain_blank(l) := regex.replace(l, `(^|[^\w])("(?:\\.|[^"\\#$])*"|'(?:\\.|[^'\\])*')`, `$1""`)

_t2(lines, i, n1) := {v |
	count(n1) > 0
	some j in helpers.span(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	not regex.match(_sanitised, l)
	some v in _assigned(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), _plain_blank(l))
}

_guarded(lines, i, n) if {
	some k in helpers.span(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_guard_re, l)
	regex.match(concat("", [`\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_tainted(lang, _, _, arg) if {
	regex.match(_src[lang], arg)
	not regex.match(_sanitised, arg)
}

_tainted(lang, lines, i, arg) if {
	not regex.match(_src[lang], arg)
	n1 := _t1(lang, lines, i)
	some n in n1 | _t2(lines, i, n1)
	regex.match(concat("", [`\b`, n, `\b`]), _plain_blank(arg))
	not _guarded(lines, i, n)
}

_blank(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`(?:\\\\.|[^`\\\\])*`", `""`)

_continues(rest) if regex.match(`[,(+.]\s*$`, rest)

_arg_text(_, _, rest) := rest if {
	trim_space(rest) != ""
	not _continues(rest)
}

_arg_text(lines, i, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, i + 3))) if {
	trim_space(rest) != ""
	_continues(rest)
}

_arg_text(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	regex.match(concat("", ["(?m)", _src[lang]]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks[lang]
	regex.match(sink.re, code)
	contains(content, sink.ctx)
	m := regex.find_all_string_submatch_n(sink.re, line, 1)
	count(m) > 0
	arg := _arg_text(lines, i, m[0][1])
	not regex.match(_wrapped, arg)
	_tainted(lang, lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Request data chooses the file of code or native library that this process loads or runs (CWE-913): a requester can make the server execute a script, plugin or library of their choosing. Map the request value to a fixed set of files instead of building a path from it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
