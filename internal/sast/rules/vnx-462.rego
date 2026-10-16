# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_462

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-462",
	"name": "Duplicate Key in Associative List (Alist)",
	"description": "Python dict literals that name the same key twice, where the later entry silently replaces the earlier one (a security setting written as True and then overridden by False further down is the dangerous case). Reported: in a multi-line dict literal (a line ending in `{`), a string or integer key written at the dict's own key indentation that an earlier entry of the same literal already used, at the later entry; and a single-line literal {...} with no nested braces that repeats a key. Single and double quotes are the same key. Not reported: the same key in sibling nested dicts or in different dicts of a list, keys that differ only in case, set literals, dicts built with dict()/update(), f-string or computed keys, comments and literals inside strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-462/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [462],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["duplicate-key", "cwe-462"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_key_re := `^\s*(?:"([^"\\]*)"|'([^'\\]*)'|(-?\d+))\s*:`

# Normalised key of an entry line: string content, or #n for an integer.
_key(l) := k if {
	m := regex.find_all_string_submatch_n(_key_re, l, 1)
	count(m) > 0
	k := _norm(m[0])
}

_norm(g) := g[1] if g[1] != ""

_norm(g) := g[2] if {
	g[1] == ""
	g[2] != ""
}

_norm(g) := concat("", ["#", g[3]]) if {
	g[1] == ""
	g[2] == ""
	g[3] != ""
}

_opens(l) if regex.match(`\{\s*(?:#.*)?$`, l)

_dup_multiline(lines, i) := js if {
	ind0 := _indent(lines[i])
	last := min([count(lines) - 1, i + 300])
	last > i
	kind := _indent(lines[i + 1])

	# the literal ends at a line back at the opener's indentation, or at a
	# closing brace left of the keys (`}, {` between two literals)
	ends := [k |
		some k in numbers.range(i + 1, last)
		_closes(lines[k], ind0, kind)
	]
	count(ends) > 0
	end := ends[0]
	end > i + 1
	entries := [[k, j] |
		some j in helpers.span(i + 1, end - 1)
		_indent(lines[j]) == kind
		k := _key(lines[j])
	]
	ks := [e[0] | some e in entries]
	count(ks) != count({k | some k in ks})
	js := {e[1] |
		some a, e in entries
		some b, f in entries
		b < a
		f[0] == e[0]
	}
}

_closes(l, ind0, _) if {
	trim_space(l) != ""
	_indent(l) <= ind0
}

_closes(l, _, kind) if {
	startswith(trim_space(l), "}")
	_indent(l) < kind
}

# The opener sits inside a triple-quoted string (an example payload, a
# docstring): an odd number of triple quotes precede it.
_in_triple_string(lines, i) if {
	n := sum([c |
		some k in numbers.range(0, i - 1)
		contains(lines[k], `"""`)
		c := count(regex.find_all_string_submatch_n(`"""`, lines[k], -1))
	])
	n % 2 == 1
}

_in_triple_string(lines, i) if {
	n := sum([c |
		some k in numbers.range(0, i - 1)
		contains(lines[k], `'''`)
		c := count(regex.find_all_string_submatch_n(`'''`, lines[k], -1))
	])
	n % 2 == 1
}

_single_dup(line) if {
	m := regex.find_all_string_submatch_n(`(?:^|[=(\[,:]|\breturn)\s*\{([^{}]*)\}`, line, -1)
	some g in m
	ents := regex.find_all_string_submatch_n(`(?:^|,)\s*(?:"([^"\\]*)"|'([^'\\]*)'|(-?\d+))\s*:`, g[1], -1)
	ks := [_norm(e) | some e in ents]
	count(ks) > 1
	count(ks) != count({k | some k in ks})
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)\{[ \t]*(?:#.*)?$`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "{")
	_opens(line)
	not helpers.is_comment_line(line)
	some j in _dup_multiline(lines, i)
	not _in_triple_string(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate key in a dict literal: this entry silently replaces the earlier one with the same key",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\{[^{}\n]*:[^{}\n]*,[^{}\n]*:`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "{")
	not helpers.is_comment_line(line)
	_single_dup(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate key in a dict literal: the later entry silently replaces the earlier one with the same key",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
