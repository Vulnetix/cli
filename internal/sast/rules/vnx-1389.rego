# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1389

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1389",
	"name": "Incorrect Parsing of Numbers with Different Radices",
	"description": "A number or address taken from outside the program is parsed by an API that guesses the radix from the text, so '010' is read as octal 8 and '0x10' as 16, and a value that passes a check in one radix means something else in another (the classic case is an IP allow-list bypassed with 0177.0.0.1). Reported: JavaScript/TypeScript parseInt() or Number.parseInt() with no radix argument when the argument is request data (req/ctx .query/.body/.params/.headers/.cookies, req.get()/req.header(), process.argv, location, URLSearchParams.get) on the same line or through a variable assigned from one within the 10 lines above; Python int(x, 0) and int(x, base=0); Go strconv.ParseInt/ParseUint(x, 0, bits); Java and Kotlin Integer/Long/Short/Byte.decode(x); C and C++ strtol/strtoul/strtoll/strtoull/strtoimax/strtoumax(x, end, 0), C++ std::stoi/stol/stoul/stoll/stoull(x, pos, 0), scanf/sscanf/fscanf with a %i conversion; and C inet_aton()/inet_addr(), which accept octal and hexadecimal octets. Not reported: an explicit radix (parseInt(x, 10), int(x, 16), ParseInt(s, 10, 64), strtol(s, NULL, 10)), parseInt of values that are not request data (style widths, lengths), string-literal arguments, Number(), Integer.parseInt/valueOf, scanf %d, inet_pton, int() wrapped in another call that takes a trailing 0 (max(int(x), 0)), wrappers whose names merely contain the API (malloc_strtoumax, myparseInt), comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1389/",
	"languages": ["node", "python", "go", "java", "kotlin", "c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1389],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["radix-parsing", "input-validation", "cwe-1389"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_c_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_jvm_exts := {".java", ".kt", ".kts"}

_is_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

# Text inside string literals removed, so a call named in a message is not a call.
_str_re := concat("", [`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`, "`(?:[^`\\\\]|\\\\.)*`"])

_code(line) := regex.replace(line, _str_re, `""`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── JavaScript / TypeScript: parseInt with one argument ────────────────────

_js_source := `\b(?:req|request|ctx)\.(?:query|body|params|headers|cookies|request)\b|\b(?:req|request|ctx)\.(?:get|header)\(|process\.argv|\blocation\.(?:search|hash|href|pathname)|searchParams\.get\(|URLSearchParams\(`

# The single argument of a radix-less parseInt / Number.parseInt: no top-level comma.
_js_single_arg_re := `(?:^|[^\w.$]|Number\.)parseInt\s*\(\s*((?:[^(),]|\([^()]*\))+?)\s*\)`

findings contains f if {
	some path, content in input.file_contents
	_is_ext(path, _js_exts)
	not endswith(path, ".min.js")
	contains(content, "parseInt")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "parseInt")
	not helpers.is_comment_line(line)
	code := _code(line)
	some m in regex.find_all_string_submatch_n(_js_single_arg_re, code, -1)
	arg := m[1]
	arg != `""`
	_js_untrusted(lines, i, arg)
	f := _finding(path, i, line, "parseInt() without a radix parses request data: '0x..' is read as hexadecimal. Pass the radix explicitly (parseInt(value, 10)) or use Number()")
}

_js_untrusted(_, _, arg) if regex.match(_js_source, arg)

_js_untrusted(lines, i, arg) if {
	some v in helpers.tainted_names(lines, i, 10, _js_source)
	regex.match(concat("", [`^\s*`, v, `\s*$`]), arg)
}

# destructuring: const { port } = req.params
_js_untrusted(lines, i, arg) if {
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(_js_source, lines[j])
	m := regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=`, lines[j], 1)
	count(m) > 0
	some name in split(m[0][1], ",")
	trim_space(name) != ""
	regex.match(concat("", [`^\s*`, trim_space(name), `\s*$`]), arg)
}

# ── Python: int(x, 0) ──────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\bint\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "int")
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(`(?:^|[^\w.])int\s*\(\s*[^"'\s)](?:[^(),]|\((?:[^()]|\([^()]*\))*\))*,\s*(?:base\s*=\s*)?0\s*\)`, code)
	f := _finding(path, i, line, "int(x, 0) infers the radix from the text: '010' and '0o10' are octal, '0x10' hexadecimal. Pass the base the input is supposed to be in (int(x, 10))")
}

# ── Go: strconv.ParseInt / ParseUint with base 0 ───────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "strconv.Parse")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "strconv.Parse")
	not helpers.is_comment_line(line)
	regex.match(`\bstrconv\.Parse(?:Int|Uint)\(\s*[^"\s][^,]*,\s*0\s*,`, line)
	f := _finding(path, i, line, "strconv.ParseInt/ParseUint with base 0 infers the radix from the prefix (0x, 0o, 0b, leading 0). Pass the base explicitly (10)")
}

# ── Java / Kotlin: Integer.decode and friends ──────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	_is_ext(path, _jvm_exts)
	contains(content, ".decode(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".decode(")
	not helpers.is_comment_line(line)
	regex.match(`\b(?:Integer|Long|Short|Byte)\.decode\(\s*[^"\s)]`, line)
	f := _finding(path, i, line, "Integer/Long.decode() treats a leading 0 as octal and 0x/# as hexadecimal. Use Integer.parseInt(s, 10) for decimal input")
}

# ── C / C++: strto*(..., 0) and inet_aton / inet_addr ──────────────────────

findings contains f if {
	some path, content in input.file_contents
	_is_ext(path, _c_exts)
	regex.match(`\b(?:strto(?:u?ll?|[iu]max)|inet_aton|inet_addr|sto(?:u?ll?|i)|[sf]?scanf)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:strto(?:u?ll?|[iu]max)|inet_aton|inet_addr|sto(?:u?ll?|i)|[sf]?scanf)\s*\(`, line)
	not helpers.is_comment_line(line)
	msg := _c_message(line)
	f := _finding(path, i, line, msg)
}

_c_message(line) := "strtol-family call with base 0 infers the radix from the text (leading 0 is octal, 0x hexadecimal). Pass the base explicitly (10)" if {
	regex.match(`(?:^|[^\w])(?:std::)?strto(?:u?ll?|[iu]max)\s*\(\s*[^"\s][^;]*,\s*0\s*\)`, line)
}

_c_strto0_re := `(?:^|[^\w])(?:std::)?strto(?:u?ll?|[iu]max)\s*\(\s*[^"\s][^;]*,\s*0\s*\)`

_c_sto0_re := `(?:^|[^\w:]|std::)sto(?:u?ll?|i)\s*\(\s*[^"\s][^;]*,\s*0\s*\)`

_c_scanf_i_re := `(?:^|[^\w])[sf]?scanf\s*\([^"]*"[^"]*%[0-9*]*(?:hh|h|ll|l|j|z|t)?i`

_c_message(line) := "std::stoi/stol/stoul with base 0 infers the radix from the text (leading 0 is octal, 0x hexadecimal). Pass the base explicitly (10)" if {
	not regex.match(_c_strto0_re, line)
	regex.match(_c_sto0_re, line)
}

_c_message(line) := "scanf-family %i conversion infers the radix from the text (leading 0 is octal, 0x hexadecimal). Use %d for decimal input" if {
	not regex.match(_c_strto0_re, line)
	not regex.match(_c_sto0_re, line)
	regex.match(_c_scanf_i_re, line)
}

_c_message(line) := "inet_aton()/inet_addr() accept octal and hexadecimal octets (0177.0.0.1 is 127.0.0.1). Use inet_pton(AF_INET, ...), which accepts dotted decimal only" if {
	not regex.match(_c_strto0_re, line)
	not regex.match(_c_sto0_re, line)
	not regex.match(_c_scanf_i_re, line)
	regex.match(`(?:^|[^\w])inet_(?:aton|addr)\s*\(\s*[^"\s)]`, line)
}
