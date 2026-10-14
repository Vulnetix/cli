package vulnetix.rules.vnx_rust_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-003",
	"name": "Rust unsafe code without a safety justification",
	"description": "An unsafe block or expression (unsafe { ... }, including let x = unsafe { ... } and match unsafe { ... }), an unsafe fn declaration (any visibility, const/async/extern \"C\" qualifiers) or an unsafe impl (Send, Sync or another unsafe trait) has no safety justification: neither a trailing comment on the same line nor the comment block directly above it (doc comments and attributes included) says why it is sound (SAFETY:, # Safety, safe, sound, invariant, guarantee, undefined behaviour). Unsafe Rust opts out of the compiler's memory-safety checks, and an undocumented unsafe region is one whose invariants nobody has written down, which is where buffer overflows and use-after-free enter Rust code. Not reported: unsafe regions that carry such a comment (the clippy undocumented_unsafe_blocks / missing_safety_doc convention), the word unsafe in a string literal, a comment, an identifier or a lint attribute such as #![forbid(unsafe_code)]. The rule does not judge whether the justification is correct.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-003/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [119],
	"capec": ["CAPEC-100"],
	"attack_technique": ["T1211"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["rust", "unsafe", "memory-safety"],
}

_block_re := `\bunsafe\s*\{`

_fn_re := `^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?unsafe\s+(?:extern\s+"[^"]*"\s+)?fn\b`

_impl_re := `^\s*unsafe\s+impl\b`

_justify_re := `(?i)safety|\bsafe\b|\bsound|invariant|guarantee|undefined behaviou?r`

# The code part of a line: string literals emptied and any trailing // comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_kind(code) := "block" if regex.match(_block_re, code)

_kind(code) := "fn" if {
	not regex.match(_block_re, code)
	regex.match(_fn_re, code)
}

_kind(code) := "impl" if {
	not regex.match(_block_re, code)
	regex.match(_impl_re, code)
}

# A trailing comment on the line itself justifies it.
_justified(lines, i) if {
	parts := split(lines[i], "//")
	count(parts) > 1
	regex.match(_justify_re, concat("//", array.slice(parts, 1, count(parts))))
}

# The contiguous comment/attribute block directly above (up to 25 lines).
_justified(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	helpers.is_comment_line(lines[j])
	regex.match(_justify_re, lines[j])
	not _code_between(lines, j, i)
}

_code_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	not helpers.is_comment_line(lines[k])
	not startswith(trim_space(lines[k]), "#[")
}

_message("block") := "unsafe block has no SAFETY comment; state why every invariant the unsafe operation needs holds here, or replace it with a safe API"

_message("fn") := "unsafe fn has no # Safety section; document the contract callers must uphold, or expose a safe wrapper instead"

_message("impl") := "unsafe impl has no SAFETY comment; explain why the type upholds the trait's safety contract (for Send/Sync: why sharing it across threads is sound)"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	contains(content, "unsafe")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "unsafe")
	not helpers.is_comment_line(line)
	k := _kind(_code(line))
	not _justified(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _message(k),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
