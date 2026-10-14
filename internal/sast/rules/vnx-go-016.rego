package vulnetix.rules.vnx_go_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-016",
	"name": "Integer downcast or sign-change after strconv.Atoi/ParseInt/ParseUint",
	"description": "The value parsed by strconv.Atoi (int), strconv.ParseInt or strconv.ParseUint (their bitSize argument gives the range, read across a call broken over lines; 0 means 64) is converted, later in the same function, to a type that cannot hold every value of that range, with no range check in between: a narrower integer (int8, int16, int32, rune, uint8, byte, uint16, uint32, os.FileMode/fs.FileMode, or a type the file declares over one of these, such as type Port uint16) truncates, a signed value converted to an unsigned type (uint, uint64...) turns negatives into huge values, and an unsigned value converted to a signed type of the same or smaller size overflows to negative. Silent wrap-around breaks limits, ports, lengths and permission checks. Not reported: a bitSize no wider than the target (strconv.ParseUint(s, 10, 16) into uint16 is already range-checked), widening conversions (int64, float64, time.Duration), a comparison of the variable against a bound other than 0 or 1 before the conversion (math.MaxUint16, 65535, 1<<16-1 and 0xffff are bounds; for truncation and overflow), any comparison for a sign change, a clamp/validation helper applied to it, int(...) of a 64-bit parse (int is 64-bit on the platforms Go servers run on), and comments or strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-016/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [681, 190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["go", "integer-truncation", "type-cast", "strconv"],
}

# conversion target -> [signed, bits]
_target := {
	"int8": [true, 8], "int16": [true, 16], "int32": [true, 32], "rune": [true, 32], "int64": [true, 64],
	"uint8": [false, 8], "byte": [false, 8], "uint16": [false, 16], "uint32": [false, 32],
	"uint64": [false, 64], "uint": [false, 64],
}

# The parsed value's range: [signed, bits].
_source(line) := [true, 64] if contains(line, "strconv.Atoi(")

_source(line) := [true, b] if {
	not contains(line, "strconv.Atoi(")
	contains(line, "strconv.ParseInt(")
	b := _bits(line, "ParseInt")
}

_source(line) := [false, b] if {
	not contains(line, "strconv.Atoi(")
	not contains(line, "strconv.ParseInt(")
	contains(line, "strconv.ParseUint(")
	b := _bits(line, "ParseUint")
}

_bits(line, fn) := b if {
	m := regex.find_all_string_submatch_n(concat("", [`strconv\.`, fn, `\([^,]+,\s*[^,]+,\s*(\d+)\s*\)`]), line, 1)
	count(m) > 0
	n := to_number(m[0][1])
	b := _norm_bits(n)
}

_bits(line, fn) := 64 if {
	not regex.match(concat("", [`strconv\.`, fn, `\([^,]+,\s*[^,]+,\s*\d+\s*\)`]), line)
}

# The parse call's text: the line, joined with its continuation lines when
# the call is broken (strconv.ParseInt(\n s, 10, 32)), so bitSize is read.
_call_text(_, _, pline) := pline if not regex.match(`strconv\.Parse(?:Int|Uint)\([^)]*$`, pline)

_call_text(lines, p, pline) := t if {
	regex.match(`strconv\.Parse(?:Int|Uint)\([^)]*$`, pline)
	end := min([count(lines) - 1, p + 2])
	t := concat(" ", [trim_space(lines[k]) | some k in numbers.range(p, end)])
}

_norm_bits(0) := 64

_norm_bits(n) := n if n != 0

# What the conversion loses, if anything.
_loss(s, t) := "truncation" if t[1] < s[1]

_loss(s, t) := "overflow" if {
	t[1] >= s[1]
	not s[0]
	t[0]
	t[1] == s[1]
}

_loss(s, t) := "sign" if {
	t[1] >= s[1]
	s[0]
	not t[0]
}

# A comparison against a bound other than 0 or 1 (1<<16-1 and 0xffff are
# bounds), or a clamp/validation call.
_upper_guard(l, v) if regex.match(concat("", [`\b`, v, `\s*\)?\s*(?:<=?|>=?)\s*(?:[A-Za-z_(-]|[2-9]|[1-9]\d|1\s*<<|0[xXbBoO])`]), l)

_upper_guard(l, v) if regex.match(concat("", [`(?:[A-Za-z_)]|[2-9]|\d\d)\s*(?:<=?|>=?)\s*`, v, `\b`]), l)

_upper_guard(l, v) if _helper_guard(l, v)

# A call named for a range check (or min/max) that takes the variable.
_helper_guard(l, v) if {
	regex.match(concat("", [`(?i)\b(?:\w*(?:valid|check|clamp|bound|range|limit)\w*|min|max)\s*\([^)]*\b`, v, `\b`]), l)
}

_sign_guard(l, v) if regex.match(concat("", [`\b`, v, `\s*\)?\s*(?:<=?|>=?)|(?:<=?|>=?)\s*`, v, `\b`]), l)

_sign_guard(l, v) if _helper_guard(l, v)

_guarded(lines, p, c, v, "sign") if {
	some k in numbers.range(p, c)
	not helpers.is_comment_line(lines[k])
	_sign_guard(_code(lines[k]), v)
}

_guarded(lines, p, c, v, kind) if {
	kind != "sign"
	some k in numbers.range(p, c)
	not helpers.is_comment_line(lines[k])
	_upper_guard(_code(lines[k]), v)
}

# Byte extraction on purpose: the same statement shifts or masks the value
# (uint8(v >> 8), uint8(v)), or masks the converted result (byte(v)&0x3f).
_deliberate(code, v, _) if regex.match(concat("", [`\b`, v, `\s*(?:>>|&[^&])`]), code)

_deliberate(code, _, conv) if contains(code, concat("", [conv, "&"]))

_deliberate(code, _, conv) if contains(code, concat("", [conv, " &"]))

# String literals and trailing comments removed.
_code(line) := c if {
	s := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`)
	c := regex.replace(s, `//.*$`, "")
}

_base_types := `int8|int16|int32|int64|rune|uint8|byte|uint16|uint32|uint64|uint`

# Named integer types: os.FileMode / fs.FileMode (uint32) and the file's own
# `type Port uint16` declarations.
_named_types(content) := object.union({"os.FileMode": "uint32", "fs.FileMode": "uint32"}, {m[1]: m[2] |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^type\s+([A-Za-z_]\w*)\s+(`, _base_types, `)\s*(?://.*)?$`]), content, -1)
})

_conv_re(named) := concat("", [`(?:^|[^\w.])(`, _base_types, `|`, concat("|", [replace(n, ".", `\.`) | some n, _ in named]), `)\(\s*([A-Za-z_]\w*)\s*\)`])

_target_of(name, _) := _target[name]

_target_of(name, named) := _target[named[name]]

_fn_end(lines, p) := e if {
	n := count(lines) - 1
	ends := [j | some j in numbers.range(min([p + 1, n]), min([p + 40, n])); startswith(lines[j], "}")]
	e := min(array.concat([min([p + 40, n])], ends))
}

_message("truncation") := "Integer parsed with strconv is converted to a narrower type without a range check; out-of-range input wraps silently. Parse with the target's bitSize (strconv.ParseInt(s, 10, 32)) or check the bounds first"

_message("overflow") := "Unsigned value parsed with strconv is converted to a signed type of the same size without a range check; large input becomes negative. Check it against the target's maximum first"

_message("sign") := "Signed value parsed with strconv is converted to an unsigned type without checking it is non-negative; negative input becomes a huge value. Reject negatives first or use strconv.ParseUint"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "strconv.")
	named := _named_types(content)
	conv_re := _conv_re(named)
	lines := split(content, "\n")
	some p, pline in lines
	contains(pline, "strconv.")
	regex.match(`strconv\.(?:Atoi|ParseInt|ParseUint)\(`, pline)
	not helpers.is_comment_line(pline)
	pcode := _code(pline)
	regex.match(`strconv\.(?:Atoi|ParseInt|ParseUint)\(`, pcode)
	v := helpers.assigned_first(pline)
	src := _source(_call_text(lines, p, pline))
	e := _fn_end(lines, p)
	p + 1 <= e
	some c in numbers.range(p + 1, e)
	line := lines[c]
	contains(line, v)
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(conv_re, _code(line), -1)
	m[2] == v
	kind := _loss(src, _target_of(m[1], named))
	not _deliberate(_code(line), v, m[0])
	not _guarded(lines, p, c, v, kind)
	finding := {
		"rule_id": metadata.id,
		"message": _message(kind),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c + 1,
		"snippet": line,
	}
}
