# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_825

import rego.v1

metadata := {
	"id": "VNX-825",
	"name": "Expired Pointer Dereference",
	"description": "Reports C and C++ pointers, references and iterators kept past the lifetime of what they point at, in five shapes. (1) The address of a non-static local (&x, or a local array) stored through a pointer-to-pointer parameter (*out = &value; *result = buf;): the caller receives a pointer into a stack frame that is gone. (2) The same address stored in a file-scope pointer (active = &cfg; current_name = local;) that the function does not reset before it returns, or in a field of a pointer parameter (c->label = buf; c->count = &n;) that the function does not overwrite later. (3) A pointer assigned the address of a local declared inside an inner block ({ char tmp[16]; label = tmp; }) and used after that block closes, before it is reassigned. (4) In C++, an iterator, reference or pointer taken from a std::vector, std::string or std::deque (begin()/end()/front()/back()/data()/c_str()/at(), &v[i], auto &r = v[i]) that is used after a call that can reallocate the container (push_back, emplace_back, emplace, insert, resize, reserve, clear, erase, assign, append, pop_back, swap, +=) and before it is refreshed (writing through a reference, head = 7, counts as a use), and a range-for over a container whose body grows or shrinks that same container. Not reported: static and heap storage, addresses of fields of pointer parameters, a global restored (assigned again) later in the function, a local shadowing the global, uses inside the block that owns the local, a pointer reassigned before use, an if block followed by else, iterators refreshed after the modification (it = v.erase(it), it = v.begin()), std::list/std::map and other node containers, comments and string literals. Returning a local's address is VNX-562; use after free() is VNX-C-004.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-825/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [825],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dangling-pointer", "iterator-invalidation", "cwe-825", "c", "cpp", "memory-safety"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_cpp_exts := {".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_fn_start(starts, i) := max(array.concat([0], [s | some s in starts; s <= i]))

_fn_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 300])
	ends := [k | some k in numbers.range(i + 1, last); startswith(lines[k], "}")]
	e := min(array.concat([last], ends))
}

# A non-static, non-extern local declaration of x (optionally an array).
_local_decl_re(x) := concat("", [`^\s+(?:(?:const|volatile|unsigned|signed|struct|enum|union|register)\s+)*[A-Za-z_][\w:]*(?:<[^;=()]*>)?\s*[*&]*\s*`, x, `\s*(\[[^\]]*\])?\s*(?:=[^;]*|\{[^;]*\})?;`])

_local_decl(lines, from, to, x, need_array) := j if {
	from <= to
	re := _local_decl_re(x)
	cands := [k |
		some k in numbers.range(from, to)
		contains(lines[k], x)
		m := regex.find_all_string_submatch_n(re, lines[k], 1)
		count(m) > 0
		_array_ok(m[0][1], need_array)
	]
	count(cands) > 0
	j := cands[count(cands) - 1]
}

_array_ok(_, false) := true

_array_ok(dim, true) if dim != ""

_need_array("") := true

_need_array(amp) := false if amp != ""

_assign_re := `^\s*(\*\s*)?([A-Za-z_]\w*)\s*=\s*(&\s*)?([A-Za-z_]\w*)\s*;`

_mention(code, v) if regex.match(concat("", [`(?:^|[^\w.>:])`, v, `\b`]), code)

_reassign(code, v) if regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), code)


# Shape 1: *out = &local through a pointer-to-pointer parameter.
_hit(lines, starts, globals, i, line, m) := [i, "the address of a local variable is stored through an out-parameter: the caller receives a pointer into this function's stack frame, which expires when it returns. Use static or heap storage, or let the caller supply the buffer"] if {
	m[1] != ""
	out := m[2]
	fs := _fn_start(starts, i)
	header := concat(" ", [lines[k] | some k in numbers.range(fs, min([i, fs + 4]))])
	regex.match(concat("", [`\*\s*\*\s*`, out, `\b`]), header)
	_local_decl(lines, max([fs + 1, i - 200]), i - 1, m[4], _need_array(m[3]))
}

# Shape 2: global = &local, not restored before the function ends.
_hit(lines, starts, globals, i, line, m) := [i, "the address of a local variable is stored in a file-scope pointer that outlives this call: any later use dereferences an expired stack frame. Reset the pointer before returning, or point it at static or heap storage"] if {
	m[1] == ""
	g := m[2]
	g in globals
	fs := _fn_start(starts, i)
	from := max([fs + 1, i - 200])
	_local_decl(lines, from, i - 1, m[4], _need_array(m[3]))
	not _local_decl(lines, from, i - 1, g, false)
	e := _fn_end(lines, i)
	not _restored(lines, i, e, g)
}

_restored(lines, i, e, g) if {
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	contains(lines[k], g)
	_reassign(_strip(lines[k]), g)
}

# Shape 3: an outer pointer keeps a block-local's address past the block.
_hit(lines, starts, globals, i, line, m) := [k, "the pointer holds the address of a variable declared in an inner block and is used after that block has closed, when the variable's lifetime is over. Declare the variable in the scope where the pointer is used"] if {
	m[1] == ""
	p := m[2]
	il := _indent(line)
	il > 0
	from := max([0, i - 40])
	openers := [k | some k in numbers.range(from, i - 1); trim_space(lines[k]) != ""; _indent(lines[k]) < il]
	count(openers) > 0
	op := openers[count(openers) - 1]
	_local_decl(lines, op + 1, i - 1, m[4], _need_array(m[3]))
	fs := _fn_start(starts, i)
	pd := _local_decl(lines, max([fs + 1, i - 200]), op, p, false)
	_indent(lines[pd]) < il
	last := min([count(lines) - 1, i + 60])
	closes := [k | some k in numbers.range(i + 1, last); trim_space(lines[k]) != ""; _indent(lines[k]) < il]
	count(closes) > 0
	c := closes[0]
	regex.match(`^\s*}\s*$`, lines[c])
	e := _fn_end(lines, c)
	uses := [k |
		some k in numbers.range(c + 1, min([e, c + 15]))
		not _is_comment(lines[k])
		_mention(_strip(lines[k]), p)
	]
	count(uses) > 0
	k := uses[0]
	not regex.match(`^\s*else\b`, lines[k])
	not _else_after(lines, c, k)
	not _reassign(_strip(lines[k]), p)
}

_else_after(lines, c, k) if {
	some j in numbers.range(c + 1, k)
	regex.match(`^\s*else\b`, lines[j])
}

# Shape 4: an iterator, reference or element pointer used after the container
# was modified. front()/back()/at()/[i] are views only when bound to a
# reference or when their address is taken; a copied value is not.
_view_res := [
	`\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*(?:\.|->)\s*(?:begin|end|cbegin|cend|rbegin|rend|data|c_str)\s*\(`,
	`&\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*(?:(?:\.|->)\s*(?:front|back|at)\s*\(|\[)`,
	`\b([A-Za-z_]\w*)\s*=\s*&\s*([A-Za-z_]\w*)\s*(?:(?:\.|->)\s*(?:front|back|at)\s*\(|\[)`,
]

_seq_container(conts, c) if c in conts

_conts_re := `\b(?:std::)?(?:vector|deque|basic_string|w?string)[ \t]*(?:<[^;(){}\n]*>)?[ \t]*[&*]?[ \t]*([A-Za-z_]\w*)[ \t]*[;,)={(\[]`

_modifier(code, c) if regex.match(concat("", [`\b`, c, `\s*(?:\.|->)\s*(?:push_back|emplace_back|emplace|insert|resize|reserve|clear|erase|assign|shrink_to_fit|append|pop_back|swap)\s*\(|\b`, c, `\s*\+=`]), code)

# The line ending the statement that starts at j.
_stmt_end(lines, j) := s if {
	last := min([count(lines) - 1, j + 10])
	ends := [k | some k in numbers.range(j, last); contains(lines[k], ";")]
	s := min(array.concat([last], ends))
}

_hit_cpp(conts, lines, i, line) := [k, "an iterator, reference or pointer into a std::vector/std::string/std::deque is used after a call that can reallocate the container, so it may point at freed storage. Take it again after the modification"] if {
	code := _strip(line)
	some vi, re in _view_res
	some m in regex.find_all_string_submatch_n(re, code, 1)
	r := m[1]
	c := m[2]
	_seq_container(conts, c)
	e := _fn_end(lines, i)
	mods := [j |
		some j in numbers.range(i + 1, min([e, i + 15]))
		contains(lines[j], c)
		not _is_comment(lines[j])
		cj := _strip(lines[j])
		_modifier(cj, c)
		not regex.match(concat("", [`\b`, r, `\s*=[^=]`]), cj)
	]
	count(mods) > 0
	md := mods[0]
	se := _stmt_end(lines, md)
	uses := [j |
		some j in numbers.range(se + 1, min([e, se + 10]))
		not _is_comment(lines[j])
		_mention(_strip(lines[j]), r)
	]
	count(uses) > 0
	k := uses[0]
	not _refreshed(vi, _strip(lines[k]), r)
	not _other_branch(lines, md, k)
}

# Assigning an iterator or pointer takes it again; assigning a reference
# (view 1, auto &r = v[i]) writes through it, which is a use.
_refreshed(vi, code, r) if {
	vi != 1
	_reassign(code, r)
}

# The use sits on another branch than the modification: an else between them
# at a shallower indentation, or the use line itself starts with else.
_other_branch(lines, md, k) if {
	im := _indent(lines[md])
	some j in numbers.range(md + 1, k)
	_indent(lines[j]) < im
	regex.match(`^\s*(?:}\s*)?else\b`, lines[j])
}

# Range-for whose body modifies the container being iterated.
_hit_cpp(conts, lines, i, line) := [j, "the body of a range-for modifies the container it iterates; a reallocation invalidates the loop's hidden iterator and the element reference. Collect the changes and apply them after the loop"] if {
	m := regex.find_all_string_submatch_n(`\bfor\s*\(\s*(?:const\s+)?auto\s*&{0,2}\s*\w+\s*:\s*([A-Za-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	c := m[0][1]
	_seq_container(conts, c)
	il := _indent(line)
	last := min([count(lines) - 1, i + 30])
	ends := [k | some k in numbers.range(i + 1, last); trim_space(lines[k]) != ""; _indent(lines[k]) <= il]
	be := min(array.concat([last], ends))
	some j in numbers.range(i + 1, be)
	contains(lines[j], c)
	not _is_comment(lines[j])
	_modifier(_strip(lines[j]), c)
}

_globals_re := `(?m)^(?:static\s+|extern\s+)?(?:(?:const|volatile|unsigned|signed|struct|enum|union)\s+)*[A-Za-z_]\w*\s*\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*(?:=[^;(]*)?;`

_arrays_re := `(?m)^\s+(?:(?:const|volatile|unsigned|signed|struct|enum|union)\s+)*[A-Za-z_]\w*\s+([A-Za-z_]\w*)\s*\[[^\]\n]*\]\s*(?:=[^;\n]*)?;`

# Only an address (&x) or a local array name can be a stack address.
_stack_rhs(m, _) if m[3] != ""

_stack_rhs(m, arrays) if m[4] in arrays

# An address-of assignment, or a local array whose name can decay to a pointer.
_has_stack_source(content, _) if regex.match(`(?m)^\s*\*?\s*[A-Za-z_]\w*\s*=\s*&\s*[A-Za-z_]\w*\s*;`, content)

_has_stack_source(_, arrays) if count(arrays) > 0

findings contains finding if {
	some path, content in input.file_contents
	some x in _exts
	endswith(path, x)
	regex.match(`(?m)^\s*\*?\s*[A-Za-z_]\w*\s*=\s*&?\s*[A-Za-z_]\w*\s*;`, content)
	arrays := {m[1] | some m in regex.find_all_string_submatch_n(_arrays_re, content, -1)}
	_has_stack_source(content, arrays)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	ms := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(ms) > 0
	_stack_rhs(ms[0], arrays)
	not _is_comment(line)
	starts := [j | some j, l in lines; regex.match(`^[A-Za-z_]`, l)]
	globals := {m[1] | some m in regex.find_all_string_submatch_n(_globals_re, content, -1)}
	some h in {r | r := _hit(lines, starts, globals, i, line, ms[0])}
	finding := _finding(path, lines, h)
}

findings contains finding if {
	some path, content in input.file_contents
	some x in _cpp_exts
	endswith(path, x)
	regex.match(`\.\s*(?:push_back|emplace_back|emplace|insert|resize|reserve|clear|erase|assign|shrink_to_fit|append|pop_back|swap)\s*\(|\+=`, content)
	conts := {m[1] | some m in regex.find_all_string_submatch_n(_conts_re, content, -1)}
	count(conts) > 0
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:\.|->)\s*(?:begin|end|cbegin|cend|rbegin|rend|data|c_str|front|back|at)\s*\(|=\s*&\s*\w+\s*\[|&\s*\w+\s*=\s*\w+\s*\[|\bfor\s*\(.*:`, line)
	not _is_comment(line)
	some h in {r | r := _hit_cpp(conts, lines, i, line)}
	finding := _finding(path, lines, h)
}
# Shape 5: a local's address stored in a field of a pointer parameter
# (c->label = buf; c->count = &n;), which the caller keeps after the frame is
# gone, and not overwritten later in the function.
_field_assign_re := `^\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_][\w.]*(?:\s*->\s*[A-Za-z_][\w.]*)*)\s*=\s*(&\s*)?([A-Za-z_]\w*)\s*;`

findings contains finding if {
	some path, content in input.file_contents
	some x in _exts
	endswith(path, x)
	regex.match(`(?m)^\s*[A-Za-z_]\w*\s*->\s*[\w.>-]+\s*=\s*&?\s*[A-Za-z_]\w*\s*;`, content)
	arrays := {m[1] | some m in regex.find_all_string_submatch_n(_arrays_re, content, -1)}
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "->")
	ms := regex.find_all_string_submatch_n(_field_assign_re, line, 1)
	count(ms) > 0
	m := ms[0]
	_stack_rhs([m[0], "", "", m[3], m[4]], arrays)
	not _is_comment(line)
	starts := [j | some j, l in lines; regex.match(`^[A-Za-z_]`, l)]
	fs := _fn_start(starts, i)
	header := concat(" ", [lines[k] | some k in numbers.range(fs, min([i, fs + 4]))])
	regex.match(concat("", [`\*\s*`, m[1], `\s*[,)]`]), header)
	_local_decl(lines, max([fs + 1, i - 200]), i - 1, m[4], _need_array(m[3]))
	e := _fn_end(lines, i)
	not _field_restored(lines, i, e, m[1], m[2])
	finding := _finding(path, lines, [i, "the address of a local variable is stored in a field of a structure the caller passed in: the caller keeps a pointer into this function's stack frame, which expires when it returns. Copy the data into storage the structure owns, or use static or heap storage"])
}

_field_restored(lines, i, e, p, f) if {
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	contains(lines[k], f)
	regex.match(concat("", [`^\s*`, p, `\s*->\s*`, f, `\s*=[^=]`]), lines[k])
}

_finding(path, lines, h) := {
	"rule_id": metadata.id,
	"message": h[1],
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": h[0] + 1,
	"snippet": lines[h[0]],
}
