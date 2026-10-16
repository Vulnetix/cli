package vulnetix.rules.vnx_py_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-002",
	"name": "eval()/exec() usage in Python",
	"description": "A call to the eval() or exec() builtin (bare, or as builtins.eval/builtins.exec), or to Pillow ImageMath.eval()/ImageMath.unsafe_eval() (which hand their expression to eval), in a .py file whose code argument is not a constant string: a variable, a request value, an f-string, a concatenation, a %-format or a .format() call, on the call line or on the next line of a call broken across lines. Whatever reaches that argument runs as Python with the process's privileges, and restricting globals (an empty __builtins__) does not sandbox it. Not reported: ast.literal_eval and other functions whose names merely contain eval, methods and definitions named eval/exec (model.eval(), app.exec(), def eval(self)), eval/exec of a constant string literal, executing the source of a file the code opens itself (exec(compile(f.read(), ...)), exec(open(path).read()), how config and startup files are loaded), and the names in comments or string literals. Whether the argument is attacker-controlled is not otherwise judged. Lines another rule says more about are reported there, not here: eval/exec of Flask/Django request data (directly or through one or two assignments in the 25 lines above) is reported by VNX-94, and exec/eval of an embedded blob decoded on the spot (base64/hex/zlib/marshal decoders, inline or through a variable) is reported by VNX-506. A decode of request data or of an encode/decode round trip is still reported here when VNX-94 does not follow it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-002/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-35"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["code-injection", "dangerous-function"],
}

# String literal contents are blanked so a call named inside a string is not
# a call, while the literal's quotes (and an f/r prefix) stay visible.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The builtin: not a method (`model.eval(`), not a definition, not a longer
# name (`literal_eval(`). builtins.eval / builtins.exec are the same function.
_call_re := `(?:^|[^\w.]|\bbuiltins\.|\bImageMath\.(?:unsafe_)?)(eval|exec)\s*\((.*)$`

# The argument is one constant literal: "...", '...', r"..." or b"...".
_constant(arg) if regex.match(`^\s*[rRbBuU]{0,2}(?:""|'')\s*(?:[,)]|$)`, arg)

# Source read from a file the code opened itself.
_file_source(arg) if regex.match(`^\s*compile\s*\(\s*[\w.]+\.read(?:_text)?\(\)`, arg)

_file_source(arg) if regex.match(`^\s*(?:compile\s*\(\s*)?(?:open|[\w.]*Path)\s*\([^()]*\)\.read(?:_text)?\(\)`, arg)

# The first argument, from the call line or (for `exec(` alone) the next
# code line.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _code(lines[j]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?:^|[^\w.]|builtins\.|ImageMath\.(?:unsafe_)?)(?:eval|exec)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:eval|exec)\s*\(`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(_call_re, c, 1)
	count(m) > 0
	fn := m[0][1]
	arg := _arg(lines, i, m[0][2])
	not _constant(arg)
	not _file_source(arg)
	not regex.match(`^\s*\)`, arg)
	not _vnx94_reports(content, lines, i, line)
	not _vnx506_reports(content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message(fn),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Lines another rule owns ──────────────────────────────────────────────
# The same eval/exec line is one problem, so it is reported once, by the rule
# that says most about it. These mirror the Python branch of VNX-94 and of
# VNX-506 exactly; keep them in step when either rule changes.

# VNX-94 (code injection): the argument carries Flask/Django request data,
# directly or through one or two assignments in the 25 lines above, with no
# numeric conversion and no allowlist check of the variable.
_v94_src := `\brequest\.(?:args|form|values|json|get_json|data|cookies|COOKIES|headers|GET|POST|body|query_params|stream)\b`

_v94_sink := `(?:^|[^\w.]|\bbuiltins\.)(?:eval|exec|compile)\s*\(`

_v94_sink_arg := `(?:^|[^\w.]|\bbuiltins\.)(?:eval|exec|compile)\s*\((.*)$`

_v94_sanitised := `\bintval\s*\(|\(int\)|\bparseInt\s*\(|\bparseFloat\s*\(|\bNumber\s*\(|(?:^|[^\w.])(?:int|float)\s*\(|\bInteger\s*\(|\bFloat\s*\(|\.to_[if]\b|\bliteral_eval\s*\(|\babs\s*\(`

_v94_assign_re := `^\s*(?:(?:final|var|let|const|val|my|local)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?\$?([A-Za-z_]\w*)\s*(?:,\s*\$?[A-Za-z_]\w*\s*)*(?::\s*[\w<>\[\]\|\. ]+?\s*)?(?::=|\.=|\+=|=)[^=~>]`

_v94_guard_re := `\bin_array\s*\(|\barray_key_exists\s*\(|\bpreg_match\s*\(|\.includes\s*\(|\.include\?\s*\(|\.has\s*\(|\bin\s+[A-Z_][A-Z0-9_]+\b|\bfullmatch\s*\(|\bre\.match\s*\(`

_v94_blank(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

_v94_plain_blank(l) := regex.replace(l, `(^|[^\w])("(?:\\.|[^"\\#$])*"|'(?:\\.|[^'\\])*')`, `$1""`)

_v94_names(line) := {v |
	m := regex.find_all_string_submatch_n(_v94_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_v94_t1(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_v94_src, l)
	not helpers.is_comment_line(l)
	not regex.match(_v94_sanitised, l)
	some v in _v94_names(l)
}

_v94_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	some v in _v94_names(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), _v94_plain_blank(l))
	not helpers.is_comment_line(l)
	not regex.match(_v94_sanitised, l)
}

_v94_guarded(lines, i, n) if {
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_v94_guard_re, l)
	regex.match(concat("", [`\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_v94_tainted(lines, i, arg) if regex.match(_v94_src, arg)

_v94_tainted(lines, i, arg) if {
	not regex.match(_v94_src, arg)
	n1 := _v94_t1(lines, i)
	some n in n1 | _v94_t2(lines, i, n1)
	regex.match(concat("", [`\b`, n, `\b`]), arg)
	not _v94_guarded(lines, i, n)
}

_v94_continues(rest) if regex.match(`[,(+.]\s*$`, rest)

_v94_arg_text(lines, i, rest) := rest if {
	trim_space(rest) != ""
	not _v94_continues(rest)
}

_v94_arg_text(lines, i, rest) := concat(" ", array.concat([rest], array.slice(lines, i + 1, i + 3))) if {
	trim_space(rest) != ""
	_v94_continues(rest)
}

_v94_arg_text(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_vnx94_reports(content, lines, i, line) if {
	regex.match(concat("", ["(?m)", _v94_src]), content)
	regex.match(_v94_sink, _v94_blank(line))
	m := regex.find_all_string_submatch_n(_v94_sink_arg, line, 1)
	count(m) > 0
	arg := _v94_arg_text(lines, i, m[0][1])
	not regex.match(_v94_sanitised, arg)
	_v94_tainted(lines, i, arg)
}

# VNX-506 (embedded malicious code): the argument is an encoded blob decoded
# on the spot (b64decode, unhexlify, zlib.decompress, marshal.loads...), inline
# or through a variable assigned from a decoder in the 15 lines above (one
# intermediate assignment), and the decoded value is not the program's own
# data run through an encode/decode round trip or read from the request.
_v506_sink := `(?:^|[^\w.])(?:exec|eval)\s*\(|\bbuiltins\.(?:exec|eval)\s*\(|__import__\(\s*["']builtins["']\s*\)\.(?:exec|eval)\s*\(`

_v506_decoder := `\b(?:b64decode|b32decode|b16decode|b85decode|a85decode|urlsafe_b64decode|decodebytes|decodestring|a2b_base64|a2b_hex|unhexlify|fromhex|marshal\.loads|zlib\.decompress|bz2\.decompress|lzma\.decompress|gzip\.decompress|codecs\.decode)\s*\(`

_v506_gate := `b64decode|b32decode|b85decode|a85decode|decodebytes|decodestring|a2b_|unhexlify|fromhex|marshal\.loads|decompress|codecs\.decode`

_v506_plain := `\b(?:b64encode|b32encode|b16encode|b85encode|a85encode|urlsafe_b64encode|encodebytes|encodestring|b2a_base64|b2a_hex|hexlify|marshal\.dumps|zlib\.compress|bz2\.compress|lzma\.compress|gzip\.compress|codecs\.encode)\s*\(|\.hex\(\)|\brequest\.(?:args|form|values|json|get_json|data|cookies|COOKIES|headers|GET|POST|body|query_params|stream|files)\b`

_v506_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_v506_inline(c) if regex.match(concat("", [`(?:`, _v506_sink, `)[^;]{0,160}?(?:`, _v506_decoder, `)`]), c)

_vnx506_reports(content, lines, i, line) if {
	regex.match(_v506_gate, content)
	regex.match(`exec|eval|Function|vm\.|execSync`, line)
	c := _v506_code(line)
	regex.match(_v506_sink, c)
	_v506_reported(lines, i, c)
}

_v506_reported(lines, i, c) if {
	_v506_inline(c)
	not regex.match(concat("", [`(?:`, _v506_decoder, `)[^;]{0,120}?(?:`, _v506_plain, `)`]), c)
}

_v506_reported(lines, i, c) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	pc := _v506_code(prev)
	regex.match(_v506_decoder, pc)
	not _v506_plain_input(lines, j, pc)
	v := helpers.assigned_ident(prev)
	_v506_sink_arg_mentions(lines, j, i, c, v)
}

_v506_sink_arg_mentions(lines, j, i, c, v) if {
	regex.match(concat("", [`(?:`, _v506_sink, `)[^;]{0,80}?\b`, v, `\b`]), c)
}

_v506_sink_arg_mentions(lines, j, i, c, v) if {
	i - 1 >= j + 1
	some k in numbers.range(j + 1, i - 1)
	mid := lines[k]
	not helpers.is_comment_line(mid)
	regex.match(concat("", [`\b`, v, `\b`]), mid)
	w := helpers.assigned_ident(mid)
	regex.match(concat("", [`(?:`, _v506_sink, `)[^;]{0,80}?\b`, w, `\b`]), c)
}

# The decoder's input is the program's own value: the decoder call itself
# reads the request or an encoder's output, or its first argument is a name
# assigned in the 15 lines above from one.
_v506_plain_input(lines, j, pc) if regex.match(concat("", [`(?:`, _v506_decoder, `)[^;]{0,120}?(?:`, _v506_plain, `)`]), pc)

_v506_plain_input(lines, j, pc) if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, _v506_decoder, `)\s*([A-Za-z_]\w*)\s*[,)]`]), pc, 1)
	count(m) > 0
	n := m[0][1]
	j > 0
	some k in numbers.range(max([0, j - 15]), j - 1)
	src := lines[k]
	not helpers.is_comment_line(src)
	helpers.assigned_ident(src) == n
	regex.match(_v506_plain, src)
}

_message("eval") := "eval() of a non-constant expression executes arbitrary code; use ast.literal_eval() for literals or a dedicated parser"

_message("exec") := "exec() of non-constant code executes arbitrary Python; replace dynamic code with explicit dispatch or importlib with an allowlist"
