package vulnetix.rules.vnx_rust_006

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-006",
	"name": "Integer truncation or sign-change cast after parsing",
	"description": "A value parsed as i64/u64 or isize/usize is immediately cast to a narrower or sign-changed integer type (e.g., as u8, as i32). Without prior range validation this silently truncates the value, potentially causing logic errors, authentication bypasses, or memory safety issues.",
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

_skip(path) if endswith(path, ".lock")

# Rust splits the parse and the cast across two statements — `let n: usize =
# s.parse()...` then `n as u8` — so requiring both on one line detected almost
# nothing. These predicates link the cast back to the declaration of the value
# being cast, whether that declaration is a `let` binding or a fn parameter.
_wide_parse_re := `\.parse\s*::\s*<\s*(i64|u64|i128|u128|isize|usize)\s*>`

_wide_decl_re := `\.parse\s*::\s*<\s*(i64|u64|i128|u128|isize|usize)\s*>|:\s*(i64|u64|i128|u128|isize|usize)\s*=`

_narrow_cast_re := `\bas\s+(u8|i8|u16|i16|u32|i32)\b`

_narrowing_parse(lines, i) if {
	regex.match(_wide_parse_re, lines[i])
	regex.match(_narrow_cast_re, lines[i])
}

_narrowing_parse(lines, i) if {
	regex.match(_narrow_cast_re, lines[i])
	helpers.has_tainted_var(lines, i, 8, _wide_decl_re)
}

# Only the genuinely lossy unsigned→signed pairs. u32 as i64 is a widening
# conversion and must not be reported.
_lossy_signed_cast(_, tgt) if tgt in {"i8", "i16", "i32"}

_lossy_signed_cast(src, tgt) if {
	tgt == "i64"
	src in {"usize", "u64"}
}

# Original same-line form (the unsigned type is named on the cast line itself)
# plus the declared-type form below.
_unsigned_signed(lines, i) if {
	regex.match(`\b(usize|u64|u32)\b`, lines[i])
	regex.match(`\bas\s+(i8|i16|i32|i64)\b`, lines[i])
}

_unsigned_signed(lines, i) if _unsigned_to_signed(lines, i)

_unsigned_to_signed(lines, i) if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_][A-Za-z0-9_]*)\s+as\s+(i8|i16|i32|i64)\b`, lines[i], 1)
	count(m) > 0
	start := max([0, i - 12])
	some j in numbers.range(start, i)
	not regex.match(`^\s*//`, lines[j])
	dm := regex.find_all_string_submatch_n(concat("", [`\b`, m[0][1], `\s*:\s*(usize|u64|u32)\b`]), lines[j], 1)
	count(dm) > 0
	_lossy_signed_cast(dm[0][1], m[0][2])
}

# Detect .parse::<i64>() or .parse::<u64>() followed on the same line (or nearby) by `as u8/i8/u16/i16/u32/i32`
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# parse() result cast to narrower type on same line
	_narrowing_parse(lines, i)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Parsing to a wide integer then immediately casting to a narrower type silently truncates; validate the value is within the target type's range before casting, or use TryFrom/TryInto for checked conversion",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect usize/u64 cast to i32/i16/i8 (sign change + possible truncation)
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	_unsigned_signed(lines, i)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Casting an unsigned integer to a signed type may produce a negative value if the high bit is set; use i64::try_from(value).map_err(...) for checked conversion",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
