# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1095

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1095",
	"name": "Loop Condition Value Update within the Loop",
	"description": "A loop changes the collection it is iterating over. Python: inside 'for x in items:' (or items.keys()/values()/items()) the body calls items.remove/pop/popitem/insert/clear/update/setdefault/add/discard or runs 'del items[...]', which skips elements of a list or raises RuntimeError for a dict or set. Java: inside an enhanced 'for (T x : items)' (or items.entrySet()/keySet()/values()) the body calls items.remove/add/addAll/removeAll/retainAll/removeIf/clear/put/putAll, which throws ConcurrentModificationException on the next iteration. Reported: the mutating statement, including one guarded on the same line (if (x) items.remove(x); / if x: items.remove(x)); a Java loop without braces has only its next statement as its body. Not reported: iteration over a copy (list(items), items[:], items.copy(), sorted(items), new ArrayList<>(items)), a mutation followed directly by break or return (the loop never resumes), list.append/extend (the deliberate worklist idiom), Iterator.remove(), files that use concurrent or copy-on-write collections (Java), and comments. While loops and index-based loops are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1095/",
	"languages": ["python", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1095],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["loop", "concurrent-modification", "reliability", "cwe-1095"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_py_loop_re := `^\s*(?:async\s+)?for\s+.+?\s+in\s+((?:self\.)?[A-Za-z_]\w*)(?:\.(?:keys|values|items)\(\))?\s*:`

_java_loop_re := `^\s*for\s*\(\s*(?:final\s+)?[\w<>\[\]?,. ]+?\s+\w+\s*:\s*((?:this\.)?[A-Za-z_]\w*)(?:\.(?:entrySet|keySet|values)\(\))?\s*\)`

_py_mut := `\.(?:remove|pop|popitem|insert|clear|update|setdefault|add|discard)\s*\(`

_java_mut := `\.(?:remove|add|addAll|removeAll|retainAll|removeIf|clear|put|putAll|putIfAbsent)\s*\(`

_esc(name) := replace(name, ".", `\.`)

# Body of the loop at line i: following lines indented deeper (Python), or up
# to the closing brace at the loop's indent (Java). 60 lines at most.
_py_body(lines, i) := [k |
	li := _indent(lines[i])
	end := min([count(lines) - 1, i + 60])
	ends := [m | some m in numbers.range(i + 1, end); i + 1 <= end; trim_space(lines[m]) != ""; _indent(lines[m]) <= li]
	e := min(array.concat([end + 1], ends))
	i + 1 <= e - 1
	some k in helpers.span(i + 1, e - 1)
]

_java_body(lines, i) := ks if {
	_java_braced(lines, i)
	ks := [k |
		li := _indent(lines[i])
		end := min([count(lines) - 1, i + 60])
		ends := [m | some m in numbers.range(i + 1, end); i + 1 <= end; _indent(lines[m]) <= li; startswith(trim_space(lines[m]), "}")]
		e := min(array.concat([end + 1], ends))
		i + 1 <= e - 1
		some k in helpers.span(i + 1, e - 1)
	]
}

# A loop without braces has one statement for its body.
_java_body(lines, i) := [k] if {
	not _java_braced(lines, i)
	k := helpers.next_code_index(lines, i, 2)
}

_java_braced(lines, i) if contains(lines[i], "{")

_java_braced(lines, i) if {
	j := helpers.next_code_index(lines, i, 2)
	startswith(trim_space(lines[j]), "{")
}

# A guard on the mutating line itself: `if (x) items.remove(x);`, `if x: items.remove(x)`.
_java_guard := `(?:(?:\}\s*)?(?:else\s+)?if\s*\(.*\)\s*\{?\s*|(?:\}\s*)?else\s*\{?\s*)?`

_py_guard := `(?:(?:el)?if\s.*:\s*|else\s*:\s*)?`

_leaves_loop(lines, k) if {
	j := helpers.next_code_index(lines, k, 3)
	regex.match(`^\s*(break|return)\b`, lines[j])
	_indent(lines[j]) >= _indent(lines[k])
}

_leaves_loop(lines, k) if regex.match(`;\s*(break|return)\b`, lines[k])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*(?:async\s+)?for\s.+\sin\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_py_loop_re, line, 1)
	count(m) > 0
	name := m[0][1]
	mut_re := concat("", [`^\s*`, _py_guard, _esc(name), _py_mut, `|^\s*`, _py_guard, `del\s+`, _esc(name), `\[`])
	some k in _py_body(lines, i)
	regex.match(mut_re, lines[k])
	not _leaves_loop(lines, k)
	finding := _finding(path, k, lines[k], name)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`for\s*\([^;)]*:`, content)
	not regex.match(`CopyOnWrite|Concurrent(Hash|Linked|Skip)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "for")
	m := regex.find_all_string_submatch_n(_java_loop_re, line, 1)
	count(m) > 0
	name := m[0][1]
	bare := trim_prefix(name, "this.")
	mut_re := concat("", [`^\s*`, _java_guard, `(?:this\.)?`, _esc(bare), _java_mut])
	some k in _java_body(lines, i)
	regex.match(mut_re, lines[k])
	not _leaves_loop(lines, k)
	finding := _finding(path, k, lines[k], name)
}

_finding(path, k, line, name) := {
	"rule_id": metadata.id,
	"message": sprintf("'%s' is modified while a loop iterates over it; iterate over a copy, collect the changes and apply them after the loop, or use an iterator's remove()", [name]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": k + 1,
	"snippet": line,
}
