package vulnetix.rules.vnx_go_016

import rego.v1

metadata := {
	"id": "VNX-GO-016",
	"name": "Integer downcast or sign-change after strconv.Atoi/ParseInt/ParseUint",
	"description": "A value parsed via strconv.Atoi(), strconv.ParseInt(), or strconv.ParseUint() is immediately cast to a narrower integer type (int8, int16, int32, uint8, uint16, uint32) or has its signedness changed without range validation. Silent truncation or sign flip can cause authentication bypasses, off-by-one errors, or memory safety issues.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-016/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [681, 190],
	"capec": ["CAPEC-92"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "integer-truncation", "type-cast", "strconv"],
}

_is_go(path) if endswith(path, ".go")

# Detect strconv.Atoi / ParseInt / ParseUint result cast to narrow type on same line
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`strconv\.(Atoi|ParseInt|ParseUint)\(`, line)
	regex.match(`\b(int8|int16|int32|uint8|uint16|uint32)\s*\(`, line)
	not regex.match(`^\s*//`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Integer parsed with strconv then immediately cast to a narrower type; validate that the parsed value is within the target type's range before casting to prevent silent truncation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Also detect on consecutive lines: parse result variable cast on next line
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`strconv\.(Atoi|ParseInt|ParseUint)\(`, line)
	not regex.match(`^\s*//`, line)
	j := i + 1
	j < count(lines)
	next := lines[j]
	regex.match(`\b(int8|int16|int32|uint8|uint16|uint32)\s*\(`, next)
	not regex.match(`^\s*//`, next)
	finding := {
		"rule_id": metadata.id,
		"message": "Integer parsed with strconv then cast to a narrower type on the next line without range validation; use bounds checks or math/bits to validate before casting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": next,
	}
}
