package vulnetix.rules.vnx_rust_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-007",
	"name": "Rust integer arithmetic overflow without checked arithmetic",
	"description": "Integer arithmetic (addition, subtraction, multiplication, left shift) is performed on a value that was just decoded from outside the program: parsed as an integer (parse::<u32>(), `let n: usize = s.parse()`, from_str_radix) or read from bytes (from_be_bytes, from_le_bytes, read_u32 and its siblings). In debug builds Rust panics on overflow, but in release builds the value wraps silently, so a decoded length plus a header, or a size product, can come out small and undersize an allocation or defeat a bounds check. Not reported: arithmetic on values that did not come from a decode, floats and strings, a value compared against a limit or clamped with min/clamp before the arithmetic, checked_*/saturating_*/wrapping_*/overflowing_* calls, and comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-007/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["rust", "integer-overflow", "arithmetic"],
}

_skip(path) if endswith(path, ".lock")

_int := `(?:u|i)(?:8|16|32|64|128|size)`

# A value decoded from outside the program.
_decode := concat("", [
	`\.parse::<`, _int, `>`,
	`|:\s*`, _int, `\s*=.*\.parse\(`,
	`|from_str_radix`,
	`|from_(?:be|le|ne)_bytes`,
	`|\.read_(?:u|i)(?:8|16|32|64)\b`,
	`|read_(?:u|i)(?:16|32|64)::<`,
])

# Arithmetic applied straight to the decoded value on the same line.
_post_arith := `(?:unwrap_or\([^)]*\)|unwrap\(\)|expect\([^)]*\)|\?|as\s+\w+)\s*(?:\+|-|\*|<<)\s*[\w(]`

_clamped := `\.(?:min|clamp)\(`

_safe_call := `checked_|saturating_|wrapping_|overflowing_`

# Strip string literals so text inside them is never arithmetic.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# The variable a line binds from a decode that is not already clamped and not
# itself arithmetic (that line is reported on its own).
_decoded_var(line) := v if {
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(_decode, code)
	not regex.match(_post_arith, code)
	not regex.match(_clamped, code)
	m := regex.find_all_string_submatch_n(`^\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_]\w*)\s*(?::\s*[\w<>:&\[\]]+\s*)?=[^=]`, code, 1)
	count(m) > 0
	v := m[0][1]
}

# Arithmetic with the variable as an operand, on either side.
_arith_on(code, v) if {
	regex.match(concat("", [`\b`, v, `\b\s*(?:\+|-|\*|<<)=?\s*[\w(]`]), code)
}

_arith_on(code, v) if {
	regex.match(concat("", [`[\w\)\]]\s*(?:\+|-|\*|<<)=?\s*\(?`, v, `\b`]), code)
}

# Compared against something, clamped, or asserted between the decode and the use.
_guarded(lines, j, i, v) if {
	i - j >= 2
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [
		`\b`, v, `\b\s*(?:>=|<=|==|!=|>|<)`,
		`|(?:>=|<=|==|!=|>|<)\s*`, v, `\b`,
		`|assert\w*!\(.*\b`, v, `\b`,
		`|\b`, v, `\.(?:min|clamp)\(`,
	]), l)
}

# Arithmetic on a variable decoded within the previous 40 lines.
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code(line)
	not regex.match(_safe_call, code)
	some j in numbers.range(max([0, i - 40]), i - 1)
	i > 0
	v := _decoded_var(lines[j])
	_arith_on(code, v)
	not _guarded(lines, j, i, v)
	finding := _finding(path, i, line)
}

# Arithmetic applied to the decode on the same line.
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code(line)
	not regex.match(_safe_call, code)
	regex.match(_decode, code)
	regex.match(_post_arith, code)
	not regex.match(_clamped, code)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Integer arithmetic on a value decoded from input without overflow protection; use checked_add()/checked_sub()/checked_mul() (or saturating_*/wrapping_*) or compare it against a limit first, since release builds wrap silently",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
