package vulnetix.rules.vnx_go_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-015",
	"name": "sync.WaitGroup.Add() called inside goroutine",
	"description": "WaitGroup.Add with a positive delta is called inside the go func literal it is meant to count, so the parent's Wait can run before the goroutine has executed Add and return early (or race with a reused WaitGroup). The WaitGroup is one declared as sync.WaitGroup in the file (variable, struct field or parameter) or named like one (wg, fooWg, waitGroup). Not reported: an Add in the parent before the go statement (including Add calls that follow an already-closed goroutine), a WaitGroup declared inside the goroutine and waited on there, a goroutine the parent already counted with an Add just before starting it, or with an Add(len(items)) immediately before the loop that starts it (its own Add calls happen while the counter is above zero), negative deltas, other Add methods (atomic counters, time.Time, big.Int, sets), and comments. A named function started with go that calls Add itself is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-015/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [362, 667],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["go", "waitgroup", "race-condition", "concurrency"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Names the file declares as a WaitGroup.
_wg_names(content) := {m[1] |
	some re in [
		`\b(\w+)\s+\*?sync\.WaitGroup\b`,
		`\b(\w+)\s*:?=\s*(?:&?sync\.WaitGroup\{|new\(sync\.WaitGroup\))`,
	]
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

_is_wg(name, names) if name in names

_is_wg(name, _) if regex.match(`(?i)(?:^wg|wg|waitgroup|waitgrp)$`, name)

# Line j is inside the block opened at line k: deeper and not closed between.
_encloses(lines, k, j) if {
	ik := _indent(lines[k])
	_indent(lines[j]) > ik
	not _closed_between(lines, k, j, ik)
}

_closed_between(lines, k, j, ik) if {
	k + 1 <= j - 1
	some m in numbers.range(k + 1, j - 1)
	_indent(lines[m]) <= ik
	startswith(trim_left(lines[m], " \t"), "}")
}

_go_re := `\bgo\s+func\s*\(`

# The innermost go func literal that encloses line a (or opens on it).
_goroutine(lines, a) := g if {
	a > 0
	cands := [k |
		some k in numbers.range(max([0, a - 80]), a - 1)
		regex.match(_go_re, lines[k])
		not helpers.is_comment_line(lines[k])
		_encloses(lines, k, a)
	]
	count(cands) > 0
	g := max(cands)
}

_goroutine(lines, a) := a if {
	regex.match(`\bgo\s+func\s*\([^)]*\)\s*\{.*\.Add\(`, lines[a])
}

# The WaitGroup is declared inside the goroutine: it is its own.
_local_to(lines, g, a, recv) if {
	g + 1 <= a - 1
	some k in numbers.range(g + 1, a - 1)
	regex.match(concat("", [`\b`, recv, `\s*:?=\s*(?:&?sync\.WaitGroup\{|new\(sync\.WaitGroup\))|\bvar\s+`, recv, `\s+sync\.WaitGroup\b`]), lines[k])
}

# The parent counted this goroutine before starting it: an Add just above
# the go statement, or an Add(len(items)) above the loop that starts it (the
# Add's block is still open at the go statement).
_counted_by_parent(lines, g, recv) if {
	_parent_add(lines, g, concat("", [`^\s*`, replace(recv, ".", `\.`), `\.Add\(`]))
}

_parent_add(lines, g, add_re) if {
	g > 0
	ig := _indent(lines[g])
	some k in numbers.range(max([0, g - 6]), g - 1)
	_indent(lines[k]) == ig
	regex.match(add_re, lines[k])
}

# wg.Add(len(items)) immediately followed by the loop that starts the
# goroutine.
_parent_add(lines, g, add_re) if {
	g > 0
	ig := _indent(lines[g])
	some k in numbers.range(max([0, g - 8]), g - 1)
	_indent(lines[k]) < ig
	regex.match(add_re, lines[k])
	f := helpers.next_code_index(lines, k, 3)
	f < g
	regex.match(`^\s*for\b`, lines[f])
	_indent(lines[f]) == _indent(lines[k])
	_encloses(lines, f, g)
}

# The Add counts a goroutine started on the next statement (the correct
# place), inside a goroutine the parent counted with some WaitGroup: the
# outer count keeps every Wait behind this Add.
_counts_next_go_in_counted(lines, g, a) if {
	g != a
	j := helpers.next_code_index(lines, a, 3)
	_indent(lines[j]) == _indent(lines[a])
	regex.match(`^\s*go\s`, lines[j])
	_parent_add(lines, g, `^\s*[A-Za-z_][\w\.]*\.Add\(`)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "go func")
	contains(content, ".Add(")
	names := _wg_names(content)
	lines := split(content, "\n")
	some a, line in lines
	contains(line, ".Add(")
	m := regex.find_all_string_submatch_n(`(?:^\s*|[{;]\s*)([A-Za-z_][\w\.]*)\.Add\(\s*([^)]*)\)`, line, 1)
	count(m) > 0
	not startswith(trim_space(m[0][2]), "-")
	recv := m[0][1]
	parts := split(recv, ".")
	_is_wg(parts[count(parts) - 1], names)
	not helpers.is_comment_line(line)
	g := _goroutine(lines, a)
	not _local_to(lines, g, a, parts[count(parts) - 1])
	not _counted_by_parent(lines, g, recv)
	not _counts_next_go_in_counted(lines, g, a)
	finding := {
		"rule_id": metadata.id,
		"message": "WaitGroup.Add() called inside the goroutine it counts; Wait() can return before the goroutine runs. Call wg.Add(n) before the go statement",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": a + 1,
		"snippet": line,
	}
}
