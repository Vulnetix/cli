package vulnetix.rules.vnx_rust_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-006",
	"name": "Integer truncation or sign-change cast after parsing",
	"description": "An integer parsed or decoded from runtime data (str::parse::<T>() or let n: T = s.parse(), T::from_str_radix, T::from_str, T::from_be_bytes / from_le_bytes / from_ne_bytes, byteorder read_u32::<E>() and friends) is converted with a lossy `as` cast: to a narrower integer type (u64 as u16, i64 as i32), from signed to unsigned (i64 as usize, where a negative value becomes huge, e.g. vec![0; n as usize]), or from unsigned to a signed type of the same or smaller width (u64 as i64). The cast is reported on the same line as the parse or on a later line within 15 lines that casts the bound variable, unless a range check on that variable comes between: a comparison (n > u16::MAX), n.min(..)/n.max(..)/n.clamp(..), (a..=b).contains(&n), match n { range arms } or matches!(n, a..=b), or a checked TryFrom/try_into conversion. A let statement split across lines (a builder chain ending in .parse()) counts as one binding; a cast in a later function of a variable with the same name does not. `as` silently truncates or reinterprets the bits, so an out-of-range input becomes a different, attacker-chosen value (CWE-681, CWE-190). Not reported: widening casts (u32 as i64, u8 as u32), casts to floating point, casts of values that were not parsed or decoded (lengths, counters, constants), comments and string literals. Values that flow through a function call or a struct field are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-006/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [681, 190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["rust", "integer-truncation", "type-cast", "numeric-safety"],
}

_int := `[iu](?:8|16|32|64|128|size)`

_width := {
	"u8": 8, "i8": 8, "u16": 16, "i16": 16, "u32": 32, "i32": 32,
	"u64": 64, "i64": 64, "u128": 128, "i128": 128, "usize": 64, "isize": 64,
}

_signed(t) if startswith(t, "i")

_lossy(s, t) if _width[t] < _width[s]

_lossy(s, t) if {
	_signed(s)
	not _signed(t)
}

_lossy(s, t) if {
	not _signed(s)
	_signed(t)
	_width[t] <= _width[s]
}

# The code part of a line: string literals emptied, trailing // comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_source_any_re := `\.parse\s*(?:::\s*<[^>]*>)?\s*\(|::from_str_radix\s*\(|::from_str\s*\(|::from_(?:be|le|ne)_bytes\s*\(|\.read_[iu](?:8|16|32|64|128)\b`

# The integer type a parse/decode expression produces, when it names one.
_rhs_type(rhs) := t if {
	m := regex.find_all_string_submatch_n(concat("", [`\.parse\s*::\s*<\s*(`, _int, `)\s*>`]), rhs, 1)
	count(m) > 0
	t := m[0][1]
} else := t if {
	m := regex.find_all_string_submatch_n(concat("", [`\b(`, _int, `)::from_(?:str_radix|str|be_bytes|le_bytes|ne_bytes)\b`]), rhs, 1)
	count(m) > 0
	t := m[0][1]
} else := t if {
	m := regex.find_all_string_submatch_n(`\.read_([iu](?:8|16|32|64|128))\b`, rhs, 1)
	count(m) > 0
	t := m[0][1]
}

# [name, type] bound by a let from a parse/decode on line `code`.
_binding(code) := [m[1], t] if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*let\s+(?:mut\s+)?([a-z_]\w*)\s*(?::\s*(`, _int, `))?\s*=\s*(.*)$`]), code, 1)[0]
	regex.match(_source_any_re, m[3])
	t := _binding_type(m)
}

_binding_type(m) := _rhs_type(m[3])

_binding_type(m) := m[2] if {
	not _rhs_type(m[3])
	m[2] != ""
}

_guard(code, v) if regex.match(concat("", [
	`\b`, v, `\s*(?:[<>]=?|==)|(?:[<>]=?)\s*`, v, `\b|\b`, v, `\s*\.\s*(?:min|max|clamp|try_into)\s*\(|contains\s*\(\s*&\s*`, v, `\b|try_from\s*\(\s*`, v, `\b|\bmatch\s+`, v, `\s*\{|\bmatches!\s*\(\s*`, v, `\s*,`,
]), code)

_cast_types(code, v) := {t |
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^.\w])`, v, `\s*\)?\s+as\s+(`, _int, `)\b`]), code, -1)
	t := m[1]
}

_parse_cast_re := concat("", [
	`(?:\.parse\s*::\s*<\s*(`, _int, `)\s*>\s*\(\s*\)|\b(`, _int, `)::from_(?:str_radix|str|be_bytes|le_bytes|ne_bytes)\s*\([^;]*?\))`,
	`(?:\s*\?|\s*\.\s*(?:unwrap|expect|unwrap_or|unwrap_or_default)\s*\([^()]*\))?\s*\)?\s+as\s+(`, _int, `)\b`,
])

_report(lines, i, code) if {
	some m in regex.find_all_string_submatch_n(_parse_cast_re, code, -1)
	src := concat("", [m[1], m[2]])
	_lossy(src, m[3])
}

_report(lines, i, code) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(`^\s*let\s`, lines[j])
	b := _binding(_stmt(lines, j))
	some t in _cast_types(code, b[0])
	_lossy(b[1], t)
	not _guarded(lines, j, i, b[0])
	not _rebound(lines, j, i, b[0])
}

_guarded(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	_guard(_code(lines[k]), v)
}

# A later let rebinds the name from something else (shadowing).
_rebound(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(concat("", [`^\s*let\s+(?:mut\s+)?`, v, `\b`]), lines[k])
}

# A new fn starts between the binding and the cast: the name there is a
# different variable (a parameter of the next function).
_rebound(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:const|async|unsafe)\s+)*fn\s`, lines[k])
}

# The let statement starting at line j, joined with up to six following lines
# when it continues (a builder chain ending in .parse() further down).
_stmt(lines, j) := code if {
	code := _code(lines[j])
	contains(code, ";")
} else := concat(" ", [_code(lines[k]) |
	some k in numbers.range(j, min([count(lines) - 1, j + 6]))
	not _ended_before(lines, j, k)
])

_ended_before(lines, j, k) if {
	some x in numbers.range(j, k - 1)
	contains(_code(lines[x]), ";")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	regex.match(concat("", [`\bas\s+`, _int, `\b`]), content)
	regex.match(_source_any_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, " as ")
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(concat("", [`\bas\s+`, _int, `\b`]), code)
	_report(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "A parsed or decoded integer is converted with a lossy `as` cast (narrowing or sign change) without a range check; out-of-range input silently becomes a different value. Use u16::try_from(n) / n.try_into() and handle the error, or check the range first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
