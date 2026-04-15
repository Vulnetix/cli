package vulnetix.rules.vnx_rust_006

import rego.v1

metadata := {
	"id": "VNX-RUST-006",
	"name": "Integer truncation or sign-change cast after parsing",
	"description": "A value parsed as i64/u64 or isize/usize is immediately cast to a narrower or sign-changed integer type (e.g., as u8, as i32). Without prior range validation this silently truncates the value, potentially causing logic errors, authentication bypasses, or memory safety issues.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-006/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [681, 190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["rust", "integer-truncation", "type-cast", "numeric-safety"],
}

_skip(path) if endswith(path, ".lock")

# Detect .parse::<i64>() or .parse::<u64>() followed on the same line (or nearby) by `as u8/i8/u16/i16/u32/i32`
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# parse() result cast to narrower type on same line
	regex.match(`\.parse\s*::\s*<\s*(i64|u64|i128|u128|isize|usize)\s*>`, line)
	regex.match(`\bas\s+(u8|i8|u16|i16|u32|i32)\b`, line)
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
	regex.match(`\b(usize|u64|u32)\b`, line)
	regex.match(`\bas\s+(i8|i16|i32|i64)\b`, line)
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
