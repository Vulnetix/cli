package vulnetix.rules.vnx_rust_007

import rego.v1

metadata := {
	"id": "VNX-RUST-007",
	"name": "Rust integer arithmetic overflow without checked arithmetic",
	"description": "Integer arithmetic (addition, subtraction, multiplication, shift) is performed without using checked_add/checked_sub/checked_mul or saturating/wrapping variants. In debug builds Rust panics on overflow, but in release builds the value wraps silently, potentially causing logic errors or security vulnerabilities.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-007/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["rust", "integer-overflow", "arithmetic"],
}

_skip(path) if endswith(path, ".lock")

# Detect integer arithmetic on size/length/index variables without checked methods
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rs")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not regex.match(`^\s*//`, line)
	# Arithmetic on variables that commonly hold sizes, offsets, or lengths
	regex.match(`\b(len|size|count|offset|index|total|sum|capacity)\s*[\+\-\*]\s`, line)
	# Not already using checked arithmetic
	not regex.match(`checked_(add|sub|mul|div)|saturating_(add|sub|mul)|wrapping_(add|sub|mul)`, line)
	# Not a const expression
	not regex.match(`const\s+\w+\s*":`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Integer arithmetic on a size/count/offset variable without overflow protection; use checked_add()/checked_sub()/checked_mul() or wrapping_*/saturating_* variants to handle overflow explicitly in release builds",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
