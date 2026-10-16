# SPDX-License-Identifier: Apache-2.0
# In-method data-flow helpers (flow_*, flow_py_*) used by the injection rules.
# Same package as helpers.rego so rules call them as helpers.flow_*; kept in
# its own file so a scan only compiles it when a selected rule uses it.

package vulnetix.helpers

import rego.v1

# ── In-method flow (flow_*): constants, dead branches, collections, calls ──
# A careful reviewer does not report `stmt.execute(sql)` just because `sql`
# was concatenated: they read the method and ask what the operand holds. The
# helpers below do that for C-family (Java-shaped) code, bounded to the
# enclosing method and at most 120 lines above the line asked about:
#
#   flow_consts(lines, i)   locals that provably hold a constant at line i: the
#                           last definition that reaches i on every path is a
#                           literal or constant expression, after folding
#                           constant if/else and ternary conditions (integer
#                           literals and single-assignment int locals), a switch
#                           on a constant, a list or map with constant indexes
#                           or keys, and a call to a method of this file whose
#                           every return is constant. Object {name: line}.
#   flow_fold(text, line, C) the text with those names (defined above `line`)
#                           replaced by "" so a rule's own "is this dynamic?"
#                           check sees a constant.
#   flow_tainted(lines, i, seeds, san)  names derived from `seeds` at line i
#                           within the method, skipping dead definitions and
#                           constant names, through assignments, for-each loops
#                           and values stored in collections or builders.
#   flow_reaches(lines, i, text, seeds, san)  whether `text` names one of them.
#   flow_xrw(lines, i, text)  the text with calls into other classes of the
#                           project replaced by what their source says they
#                           return: "" for a constant, the argument for a
#                           method that returns a function of it (see the
#                           "Cross-file method summaries" section). Applied
#                           inside flow_consts, flow_tainted and flow_reaches;
#                           a rule folding text itself calls it first.
#
# Inert calls. A call into code this file cannot see (`helper.make("lit")`,
# `Cls.of(CONST)`, a `new Box("x")` held in a local) is inert, and its value constant,
# when (1) its name is not source-like (read*, next*, getParameter*,
# getHeader*, getCookie*, getenv, getProperty, query, execute, ...), (2) every
# argument is a literal or a name flow_consts holds, and (3) its receiver is a
# type name, a `new` with constant arguments, or a local whose own definition
# is such a call and which is only ever called with constant arguments (a
# `box.add(tainted)` anywhere above disqualifies `box`). The value of an
# inert call is a constant in flow_consts, flow_fold folds it, and
# flow_tainted therefore does not carry taint through it; a call that fails
# any test stays unresolved, so a helper handed a tainted argument, a tainted
# receiver or a source-like name is still reported. The Python flow_py_* family
# applies the same principle (classes, imported modules and locals).
#
# Anything the helpers cannot resolve is not constant: a rule that drops a
# finding only on flow_consts never drops one because the analysis gave up.

_flow_kw := {"if", "else", "for", "while", "switch", "case", "return", "new", "this", "super", "throw", "catch", "try", "do", "synchronized", "default", "final", "assert", "yield"}

_flow_blank(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)+'`, `''`)

_flow_code(l) := "" if is_comment_line(l)

_flow_code(l) := regex.replace(_flow_blank(l), `//.*$|/\*.*?\*/`, "") if not is_comment_line(l)

_flow_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)+(?:<[^>]*>\s+)?[\w.$<>\[\], ?]+\s+(\w+)\s*\(`

_flow_decl_pp_re := `^\s*(?:<[^>]*>\s+)?([\w.$<>\[\]]+)\s+(\w+)\s*\([^;=]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$`

_flow_is_decl(l) if {
	contains(l, "(")
	regex.match(_flow_decl_re, l)
}

_flow_is_decl(l) if regex.match(`^\s*(?:public|protected|private)\s+[A-Z]\w*\s*\([^;]*$`, l)

_flow_is_decl(l) if {
	contains(l, "{")
	m := regex.find_all_string_submatch_n(_flow_decl_pp_re, l, 1)
	count(m) > 0
	not m[0][1] in _flow_kw
	not m[0][2] in _flow_kw
}

# The first line of the method body enclosing line i (at most 120 above).
_flow_start(lines, i) := d + 1 if {
	ds := [k | some k in numbers.range(max([0, i - 120]), i - 1); k < i; _flow_is_decl(lines[k])]
	count(ds) > 0
	d := max(ds)
} else := max([0, i - 120])

# Per-line facts for the window [s, i]: code text (strings blanked, comments
# removed), brace delta, depth at the start of the line, and the lowest depth
# the line reaches before it opens anything (`} else {` closes first).
_flow_ctx(lines, i) := ctx if {
	i > 0
	s := _flow_start(lines, i)
	bl := [_flow_code(lines[k]) | some k in numbers.range(s, i)]
	dl := [_flow_delta(b) | some b in bl]
	dep := [sum(array.slice(dl, 0, n)) | some n in numbers.range(0, count(dl) - 1)]
	low := [x | some n in numbers.range(0, count(bl) - 1); x := dep[n] - count(regex.find_n(`\}`, regex.replace(bl[n], `\{.*$`, ""), -1))]
	base := {"s": s, "t": i - s, "b": bl, "dl": dl, "dep": dep, "low": low}
	defs := _flow_defs(base)
	ctx := object.union(base, {"defs": defs, "ints": _flow_ints(base, defs, lines)})
}

_flow_prefix_re := `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?(?:(?:case\s+[^:]+|default)\s*:\s*)?`

_flow_asg_re := `^(?:final\s+)?(?:[\w.$]+(?:<[^=;]*>)?(?:\[\])*\s+)?([A-Za-z_]\w*)\s*(\+?=)(?:[^=]|$)`

# Assignments in the window above the asked line: {v, n (window index), op}.
_flow_defs(ctx) := [d |
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.b[n]
	contains(b, "=")
	m := regex.find_all_string_submatch_n(_flow_asg_re, regex.replace(b, _flow_prefix_re, ""), 1)
	count(m) > 0
	not m[0][1] in _flow_kw
	d := {"v": m[0][1], "n": n, "op": m[0][2]}
]

# v is changed other than by the assignments _flow_defs recognised.
_flow_mutated(ctx, defs, v) if {
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.b[n]
	contains(b, v)
	regex.match(concat("", [`(?:^|[^\w.$])`, v, `\s*(?:[-*/%&|^]|<<|>>>?)=|(?:^|[^\w.$])`, v, `\s*(?:\+\+|--)|(?:\+\+|--)\s*`, v, `\b`]), b)
}

_flow_mutated(ctx, defs, v) if {
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.b[n]
	contains(b, v)
	k := count(regex.find_n(concat("", [`(?:^|[^\w.$])`, v, `\s*\+?=(?:[^=]|$)`]), b, -1))
	k > count([1 | some d in defs; d.n == n; d.v == v])
}

_flow_single(ctx, defs, v) if {
	count([1 | some d in defs; d.v == v]) == 1
	not _flow_mutated(ctx, defs, v)
}

# Integer locals assigned once, from an integer literal.
_flow_ints(ctx, defs, lines) := {v: to_number(m[0][2]) |
	some d in defs
	d.op == "="
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:int|long|short|byte)\s+([A-Za-z_]\w*)\s*=\s*(-?\d{1,9})[lL]?\s*;`, lines[ctx.s + d.n], 1)
	count(m) > 0
	v := m[0][1]
	v == d.v
	_flow_single(ctx, defs, v)
}

# ── Constant conditions ──────────────────────────────────────────────────

# "t" or "f" for a condition built only from integer literals, those integer
# locals, arithmetic and one comparison (or a bare true/false); undefined
# otherwise.
_flow_cond(ctx, c) := r if {
	toks := regex.find_n(`\d+|[A-Za-z_]\w*|>=|<=|==|!=|&&|\|\||[-+*/%()<>!]|\S`, trim_space(c), -1)
	count(toks) > 0
	every x in toks {
		_flow_tok_ok(ctx, x)
	}
	s := concat("", [_flow_tok(ctx, x) | some x in toks])
	r := _flow_eval_cond(s)
}

_flow_tok_ok(_, x) if regex.match(`^(?:\d+|>=|<=|==|!=|[-+*/%()<>])$`, x)

_flow_tok_ok(_, x) if x in {"true", "false"}

_flow_tok_ok(ctx, x) if _ = ctx.ints[x]

_flow_tok(ctx, x) := format_int(ctx.ints[x], 10) if _ = ctx.ints[x]

_flow_tok(ctx, x) := x if not ctx.ints[x]

_flow_eval_cond("true") := "t"

_flow_eval_cond("false") := "f"

_flow_eval_cond(s) := r if {
	m := regex.find_all_string_submatch_n(`^([^<>=!]+)(>=|<=|==|!=|>|<)([^<>=!]+)$`, s, 1)
	count(m) > 0
	a := _flow_arith(m[0][1])
	b := _flow_arith(m[0][3])
	r := _flow_cmp(a, m[0][2], b)
}

_flow_cmp(a, ">", b) := "t" if a > b
else := "f"

_flow_cmp(a, "<", b) := "t" if a < b
else := "f"

_flow_cmp(a, ">=", b) := "t" if a >= b
else := "f"

_flow_cmp(a, "<=", b) := "t" if a <= b
else := "f"

_flow_cmp(a, "==", b) := "t" if a == b
else := "f"

_flow_cmp(a, "!=", b) := "t" if a != b
else := "f"

_flow_arith(s) := to_number(r) if {
	p := _flow_paren(_flow_paren(_flow_paren(s)))
	not contains(p, "(")
	r := _flow_flat(p)
}

_flow_paren(s) := s if not contains(s, "(")

_flow_paren(s) := strings.replace_n(rep, s) if {
	contains(s, "(")
	ms := regex.find_n(`\([^()]*\)`, s, -1)
	count(ms) > 0
	rep := {m: v | some m in ms; v := _flow_flat(trim(m, "()"))}
	count(rep) == count({m | some m in ms})
}

# A flat integer expression, * / % before + -, left to right.
_flow_flat(s) := r if {
	m := _flow_mul(_flow_mul(_flow_mul(_flow_mul(_flow_mul(s)))))
	r := _flow_add(_flow_add(_flow_add(_flow_add(_flow_add(m)))))
	regex.match(`^-?\d+$`, r)
}

_flow_mul(s) := r if {
	ms := regex.find_all_string_submatch_n(`(\d+)([*/%])(\d+)`, s, 1)
	count(ms) > 0
	v := _flow_op(to_number(ms[0][1]), ms[0][2], to_number(ms[0][3]))
	p := indexof(s, ms[0][0])
	r := concat("", [substring(s, 0, p), format_int(v, 10), substring(s, p + count(ms[0][0]), -1)])
} else := s

_flow_add(s) := r if {
	ms := regex.find_all_string_submatch_n(`^(-?\d+)([-+])(\d+)`, s, 1)
	count(ms) > 0
	v := _flow_op(to_number(ms[0][1]), ms[0][2], to_number(ms[0][3]))
	r := concat("", [format_int(v, 10), substring(s, count(ms[0][0]), -1)])
} else := s

_flow_op(a, "*", b) := a * b

_flow_op(a, "+", b) := a + b

_flow_op(a, "-", b) := a - b

_flow_op(a, "/", b) := (a - (a % b)) / b if b != 0

_flow_op(a, "%", b) := a % b if b != 0

# ── Which definitions reach the asked line ───────────────────────────────

# "dom": the definition runs on every path to the target and nothing later
# in its block can skip it; "dead": it is on a branch a constant condition or
# switch never takes; "cond": anything else.
_flow_status(ctx, lines, n, t) := "dead" if _flow_guard(ctx, n) == "f"
else := "cond" if _flow_guard(ctx, n) == "?"
else := "dom" if _flow_min_low(ctx, n, t) >= ctx.dep[n]
else := _flow_block_status(ctx, lines, n, t)

_flow_min_low(ctx, n, t) := min(array.slice(ctx.low, n + 1, t + 1))

_flow_if_re := `^\s*(?:\}\s*)?(else\s+)?if\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`

# The guard written on the line itself or on a braceless line above it:
# "t" taken (or none), "f" never taken, "?" unknown.
_flow_guard(ctx, n) := g if {
	m := regex.find_all_string_submatch_n(concat("", [_flow_if_re, `\s*[^\s{]`]), ctx.b[n], 1)
	count(m) > 0
	g := _flow_if_guard(ctx, m[0][1], m[0][2])
} else := g if {
	regex.match(`^\s*(?:\}\s*)?else\s+\w`, ctx.b[n])
	not regex.match(`^\s*(?:\}\s*)?else\s+if\b`, ctx.b[n])
	g := _flow_else_guard(ctx, n)
} else := g if {
	p := _flow_prev_code(ctx, n)
	m := regex.find_all_string_submatch_n(concat("", [_flow_if_re, `\s*$`]), ctx.b[p], 1)
	count(m) > 0
	g := _flow_if_guard(ctx, m[0][1], m[0][2])
} else := g if {
	p := _flow_prev_code(ctx, n)
	regex.match(`^\s*(?:\}\s*)?else\s*$`, ctx.b[p])
	g := _flow_else_guard(ctx, p)
} else := "?" if {
	# the line above does not end a statement: a braceless loop or a
	# condition continued over several lines guards this one
	p := _flow_prev_code(ctx, n)
	not regex.match(`[;{}:]\s*$`, ctx.b[p])
} else := "t"

_flow_if_guard(ctx, e, c) := "?" if e != ""
else := v if v := _flow_cond(ctx, c)
else := "?"

_flow_prev_code(ctx, n) := max(ps) if {
	ps := [p | some p in numbers.range(max([0, n - 3]), n - 1); p < n; p >= 0; trim_space(ctx.b[p]) != ""]
	count(ps) > 0
}

# The else on line n belongs to the nearest if above at its depth; it is
# taken exactly when that if's constant condition is false.
_flow_else_guard(ctx, n) := g if {
	ms := [m |
		some m in numbers.range(max([0, n - 8]), n - 1)
		m >= 0
		m < n
		ctx.dep[m] == ctx.low[n]
		regex.match(`^\s*(?:\}\s*)?if\s*\(`, ctx.b[m])
	]
	count(ms) > 0
	m := max(ms)
	not _flow_elseif_between(ctx, m, n)
	c := regex.find_all_string_submatch_n(_flow_if_re, ctx.b[m], 1)[0][2]
	v := _flow_cond(ctx, c)
	g := {"t": "f", "f": "t"}[v]
} else := "?"

_flow_elseif_between(ctx, m, n) if {
	some k in numbers.range(m + 1, n)
	regex.match(`\belse\s+if\b`, ctx.b[k])
}

# The definition is inside a block that closes before the target: the block
# decides. One level: a constant if/else or a switch on a constant.
_flow_block_status(ctx, lines, n, t) := st if {
	d := ctx.dep[n]
	os := [o |
		some o in numbers.range(max([0, n - 120]), n - 1)
		o >= 0
		o < n
		ctx.dep[o] + ctx.dl[o] == d
		endswith(trim_space(ctx.b[o]), "{")
	]
	count(os) > 0
	st := _flow_opener_status(ctx, lines, max(os), n, t, d)
} else := "cond"

_flow_opener_status(ctx, lines, o, n, t, d) := st if {
	m := regex.find_all_string_submatch_n(concat("", [_flow_if_re, `\s*\{\s*$`]), ctx.b[o], 1)
	count(m) > 0
	m[0][1] == ""
	v := _flow_cond(ctx, m[0][2])
	st := _flow_taken(ctx, v, n, t, d)
} else := st if {
	regex.match(`^\s*(?:\}\s*)?else\s*\{\s*$`, ctx.b[o])
	ps := [p |
		some p in numbers.range(max([0, o - 120]), o - 1)
		p >= 0
		p < o
		ctx.dep[p] + ctx.dl[p] == d
		endswith(trim_space(ctx.b[p]), "{")
	]
	count(ps) > 0
	m := regex.find_all_string_submatch_n(concat("", [_flow_if_re, `\s*\{\s*$`]), ctx.b[max(ps)], 1)
	count(m) > 0
	m[0][1] == ""
	v := _flow_cond(ctx, m[0][2])
	st := _flow_taken(ctx, {"t": "f", "f": "t"}[v], n, t, d)
} else := st if {
	regex.match(`^\s*switch\s*\(`, ctx.b[o])
	m := regex.find_all_string_submatch_n(`^\s*switch\s*\((.*)\)\s*\{\s*(?://.*)?$`, lines[ctx.s + o], 1)
	count(m) > 0
	st := _flow_switch_status(ctx, lines, o, n, t, d, trim_space(m[0][1]))
} else := "cond"

_flow_taken(_, "f", _, _, _) := "dead"

_flow_taken(ctx, "t", n, t, d) := "dom" if _flow_min_low(ctx, n, t) >= d - 1

_flow_taken(ctx, "t", n, t, d) := "cond" if _flow_min_low(ctx, n, t) < d - 1

# ── Switch on a constant ─────────────────────────────────────────────────

_flow_label_re := `^\s*(?:case\s+('(?:[^'\\]|\\.)+'|"(?:[^"\\]|\\.)*"|-?\d+|[\w.$]+)|(default))\s*(?::|->)`

_flow_label_only_re := `^\s*(?:case\s+(?:'(?:[^'\\]|\\.)+'|"(?:[^"\\]|\\.)*"|-?\d+|[\w.$]+)|default)\s*:\s*(?://.*)?$`

_flow_label(raw) := "default" if {
	m := regex.find_all_string_submatch_n(_flow_label_re, raw, 1)
	m[0][2] == "default"
}

_flow_label(raw) := _flow_norm(m[0][1]) if {
	m := regex.find_all_string_submatch_n(_flow_label_re, raw, 1)
	m[0][1] != ""
}

_flow_norm(x) := concat("", ["c:", substring(x, 1, count(x) - 2)]) if startswith(x, "'")

_flow_norm(x) := concat("", ["s:", substring(x, 1, count(x) - 2)]) if startswith(x, "\"")

_flow_norm(x) := concat("", ["n:", format_int(to_number(x), 10)]) if regex.match(`^-?\d+$`, x)

_flow_switch_status(ctx, lines, o, n, t, d, selx) := st if {
	sel := _flow_selector(ctx, lines, selx)
	ends := [k | some k in numbers.range(o + 1, t); k > o; ctx.low[k] < d]
	e := min(array.concat(ends, [t + 1]))
	labs := {k: l |
		some k in span(o + 1, e - 1)
		k > o
		k < e
		ctx.dep[k] == d
		l := _flow_label(lines[ctx.s + k])
	}
	count([k | some k, _ in labs; k <= n]) > 0
	st := _flow_case_status(ctx, lines, labs, o, n, t, d, e, sel)
} else := "cond"

_flow_case_status(ctx, lines, labs, o, n, t, d, e, sel) := st if {
	all := {l | some _, l in labs}
	selk := [k | some k, l in labs; _flow_selected(l, sel, all)]
	count(selk) > 0
	sk := min(selk)
	# the selected group must end in break/return/throw before the next group
	nexts := [k | some k, _ in labs; k > sk; not regex.match(_flow_label_only_re, lines[(ctx.s + k) - 1])]
	ne := min(array.concat(nexts, [e]))
	regex.match(`\b(?:break|return|throw|continue)\b`, concat(" ", array.slice(ctx.b, sk, ne)))
	g := max([k | some k, _ in labs; k <= n])
	gl := _flow_group(lines, ctx, labs, g)
	st := _flow_case_pick(ctx, gl, sel, all, n, t, d)
} else := "cond"

_flow_case_pick(ctx, gl, sel, all, n, t, d) := _flow_taken(ctx, "t", n, t, d) if {
	some l in gl
	_flow_selected(l, sel, all)
} else := "dead"

_flow_selected(l, sel, _) if l == sel

_flow_selected("default", sel, all) if not sel in all

# The labels of the case group that starts at or above label line g.
_flow_group(lines, ctx, labs, g) := {labs[k] |
	some k in numbers.range(max([0, g - 3]), g)
	_ = labs[k]
	every m in numbers.range(k, g) {
		_flow_in_group(lines, ctx, m, g)
	}
}

_flow_in_group(_, _, g, g)

_flow_in_group(lines, ctx, m, g) if {
	m != g
	regex.match(_flow_label_only_re, lines[ctx.s + m])
}

# The value a switch selects on, when it is a literal or a local holding one.
_flow_selector(_, _, x) := _flow_norm(x) if regex.match(`^(?:'(?:[^'\\]|\\.)+'|"(?:[^"\\]|\\.)*"|-?\d+)$`, x)

_flow_selector(ctx, _, x) := concat("", ["n:", format_int(ctx.ints[x], 10)]) if _ = ctx.ints[x]

_flow_selector(ctx, lines, x) := v if {
	regex.match(`^[A-Za-z_]\w*$`, x)
	not ctx.ints[x]
	r := _flow_single_rhs(ctx, lines, x)
	v := _flow_lit_or_charat(ctx, lines, r)
}

_flow_selector(ctx, lines, x) := _flow_charat(ctx, lines, x) if contains(x, "charAt")

_flow_lit_or_charat(_, _, r) := _flow_norm(r) if regex.match(`^(?:'[^'\\]+'|"[^"\\]*"|-?\d+)$`, r)

_flow_lit_or_charat(ctx, lines, r) := _flow_charat(ctx, lines, r) if {
	not startswith(r, "\"")
	contains(r, "charAt")
}

_flow_charat(ctx, lines, x) := concat("", ["c:", substring(s, to_number(m[0][2]), 1)]) if {
	m := regex.find_all_string_submatch_n(`^("[^"\\]*"|[A-Za-z_]\w*)\s*\.\s*charAt\s*\(\s*(\d+)\s*\)$`, x, 1)
	count(m) > 0
	s := _flow_strlit(ctx, lines, m[0][1])
	to_number(m[0][2]) < count(s)
}

_flow_strlit(_, _, x) := substring(x, 1, count(x) - 2) if regex.match(`^"[^"\\]*"$`, x)

_flow_strlit(ctx, lines, x) := substring(r, 1, count(r) - 2) if {
	regex.match(`^[A-Za-z_]\w*$`, x)
	r := _flow_single_rhs(ctx, lines, x)
	regex.match(`^"[^"\\]*"$`, r)
}

_flow_single_rhs(ctx, lines, x) := trim_space(r) if {
	_flow_single(ctx, ctx.defs, x)
	some d in ctx.defs
	d.v == x
	d.op == "="
	r := _flow_rhs(lines, ctx.s + d.n, x)
}

# ── Right-hand sides and what they need to be constant ───────────────────

_flow_rhs(lines, j, v) := m[0][1] if {
	txt := concat(" ", array.slice(lines, j, min([count(lines), j + 16])))
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])`, v, `\s*\+?=([^=](?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^;"'])*)`]), txt, 1)
	count(m) > 0
}

_flow_cast_re := `\(\s*(?:final\s+)?(?:java\.lang\.)?(?:String|Object|CharSequence|int|long|short|byte|char|double|float|boolean|Integer|Long|Short|Byte|Character|Double|Float|Boolean)\s*\)`

# [text, line] pairs that must all be constant for the value of `r` (on line
# j, window index n) to be constant: the taken side of a constant ternary,
# both sides otherwise, collection reads resolved to the value stored.
_flow_reqs_of(ctx, lines, r, j, n, M) := q if {
	rb := _flow_blank(r)
	tm := regex.find_all_string_submatch_n(`^([^?]*)\?([^:]*):(.*)$`, rb, 1)
	count(tm) > 0
	q := _flow_tern(_flow_tern_cond(ctx, tm[0][1]), tm[0][2], tm[0][3], j)
} else := _flow_expr_reqs(ctx, lines, r, j, n, M)

_flow_tern_cond(ctx, c) := v if v := _flow_cond(ctx, c)
else := "?"

_flow_tern("t", a, _, j) := [[a, j]]

_flow_tern("f", _, b, j) := [[b, j]]

_flow_tern("?", a, b, j) := [[a, j], [b, j]]

_flow_get_re := `\b([A-Za-z_]\w*)\s*\.\s*get\s*\(\s*("(?:[^"\\]|\\.)*"|\d+)\s*\)`

_flow_expr_reqs(ctx, lines, r, j, n, M) := array.concat(array.concat([[i4.t, j]], [x[1] | some x in res]), array.concat(array.concat(i1.q, i4.q), array.concat(i2.q, i3.q))) if {
	gets := regex.find_all_string_submatch_n(_flow_get_re, r, -1)
	res := [[g[0], e] | some g in gets; e := _flow_cget(ctx, lines, g[1], g[2], n)]
	r1 := strings.replace_n({x[0]: `""` | some x in res}, r)
	r2 := _flow_drop_calls(r1, M)
	i1 := _flow_inert_round(ctx, r2, j)
	i2 := _flow_inert_round(ctx, i1.t, j)
	i3 := _flow_inert_round(ctx, i2.t, j)
	i4 := _flow_inert_round(ctx, i3.t, j)
}

# ── Inert calls ──────────────────────────────────────────────────────────
# A call into code the analysis cannot see is inert when it cannot bring
# run-time data in: it is not named like a source, every argument is a
# constant (a literal, or a name C holds), and its receiver is a type name, a
# `new` expression with constant arguments, or a local that is itself such a
# value and is only ever used as the receiver of calls with constant
# arguments. The value of an inert call is constant. Each condition is a
# requirement checked against C, so a call handed a tainted argument, called
# on a tainted receiver or named like a source stays unresolved.

_flow_inert_re := `(^|[^\w.$])(new\s+)?((?:[A-Za-z_][\w$]*\s*\.\s*)*)([A-Za-z_][\w$]*)\s*\(((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^()"'])*)\)`

# Methods that read from the outside world, or start something.
_flow_srcname_re := `^(?:(?:read|next|recv|receive|query|execute|exec|fetch|load|open|poll|take|pop|accept|input|stdin|lines|scan|connect|lookup|resolve|run|call|invoke|spawn|start|eval|getenv|getProp|getSys)\w*|get\w*(?:Param|Header|Cookie|Query|Input|Reader|Stream|Body|Attr|Session|Request|Remote|Env|Prop|Uri|Url|Path|Data|Value|Line|Content|Text|Message|Result|Resource|Socket|Arg|Host|Addr)\w*)$`

# Types whose construction reads or runs something.
_flow_srctype_re := `(?:Reader|Stream|Scanner|Socket|Channel|Connection|Client|Request|Session|Process|Statement|Runtime|Console)$`

_flow_inert_kind(m) := ["new", ""] if {
	m[2] != ""
	regex.match(`^[A-Z]`, m[4])
	not regex.match(_flow_srctype_re, m[4])
	regex.match(`^(?:\s*[a-z]\w*\s*\.)*\s*$`, m[3])
}

_flow_inert_kind(m) := ["type", ""] if {
	m[2] == ""
	m[3] != ""
	not regex.match(_flow_srcname_re, m[4])
	ch := regex.replace(m[3], `\s+`, "")
	regex.match(`^(?:[a-z]\w*\.)*[A-Z]\w*[a-z]\w*\.$`, ch)
	not regex.match(_flow_srctype_re, trim_suffix(ch, "."))
}

_flow_inert_kind(m) := ["local", trim_suffix(ch, ".")] if {
	m[2] == ""
	not regex.match(_flow_srcname_re, m[4])
	ch := regex.replace(m[3], `\s+`, "")
	regex.match(`^[a-z_]\w*\.$`, ch)
	not trim_suffix(ch, ".") in _flow_kw
}

# The inert candidates in text r: whole match without its lead, kind,
# receiver local, argument text.
_flow_inert_hits(r) := [h |
	contains(r, "(")
	some m in regex.find_all_string_submatch_n(_flow_inert_re, r, -1)
	not m[4] in _flow_kw
	k := _flow_inert_kind(m)
	h := {"all": substring(m[0], count(m[1]), -1), "kind": k[0], "recv": k[1], "args": m[5]}
]

# One round: inert calls replaced by "", with what must hold for each.
_flow_inert_round(ctx, r, j) := {"t": strings.replace_n({h.all: `""` | some h in hs}, r), "q": [q |
	some h in hs
	some q in _flow_inert_reqs(ctx, h, j)
]} if {
	hs := _flow_inert_hits(r)
	count(hs) > 0
} else := {"t": r, "q": []}

_flow_inert_reqs(ctx, h, j) := array.concat(_flow_args_req(h, j), _flow_recv_reqs(ctx, h, j))

_flow_args_req(h, j) := [[h.args, j]] if trim_space(h.args) != ""

_flow_args_req(h, _) := [] if trim_space(h.args) == ""

_flow_recv_reqs(ctx, h, j) := array.concat([[h.recv, j]], _flow_call_mentions(ctx, h.recv)) if h.kind == "local"

_flow_recv_reqs(_, h, _) := [] if h.kind != "local"

# Every call on local v above the asked line must have constant arguments
# (v.append(tainted) makes v run-time data).
_flow_mention_args(ctx, v) := [[a[1], ctx.s + k] |
	some k in numbers.range(0, ctx.t - 1)
	k < ctx.t
	contains(ctx.b[k], v)
	st := _flow_stmt_from(ctx, v, k)
	some a in regex.find_all_string_submatch_n(`\.\s*[A-Za-z_]\w*\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, st, -1)
	trim_space(a[1]) != ""
]

# The arguments of those calls, with the type-level inert calls inside them
# folded (a local receiver nested in an argument is left unresolved).
_flow_call_mentions(ctx, v) := [q |
	some x in _flow_mention_args(ctx, v)
	some q in _flow_static_reqs(x[0], x[1])
]

_flow_static_reqs(a, j) := array.concat([[s3.t, j]], array.concat(s1.q, array.concat(s2.q, s3.q))) if {
	s1 := _flow_static_round(a, j)
	s2 := _flow_static_round(s1.t, j)
	s3 := _flow_static_round(s2.t, j)
}

_flow_static_round(r, j) := {"t": strings.replace_n({h.all: `""` | some h in hs}, r), "q": [[h.args, j] | some h in hs; trim_space(h.args) != ""]} if {
	hs := [h | some h in _flow_inert_hits(r); h.kind != "local"]
	count(hs) > 0
} else := {"t": r, "q": []}

# The statement text from the first use of v on line k: the line and the
# lines that continue it up to the `;`.
_flow_stmt_from(ctx, v, k) := rest if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])(`, v, `\s*\..*)$`]), ctx.b[k], 1)
	count(m) > 0
	e := min(array.concat([x | some x in numbers.range(k, min([ctx.t - 1, k + 6])); contains(ctx.b[x], ";")], [min([ctx.t - 1, k + 6])]))
	rest := concat(" ", array.concat([m[0][1]], [ctx.b[x] | some x in numbers.range(k + 1, e); x > k; x <= e]))
}

_flow_drop_calls(r, M) := r if count(M.m) == 0

_flow_drop_calls(r, M) := strings.replace_n({x[0]: `""` |
	some x in regex.find_all_string_submatch_n(`(?:\bnew\s+([A-Z]\w*)\s*\(\s*\)\s*\.\s*|\bthis\s*\.\s*|\b([A-Z]\w*)\s*\.\s*)?\b([a-z_]\w*)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`, r, -1)
	x[3] in M.m
	_flow_recv_ok(x, M.c)
}, r) if count(M.m) > 0

_flow_recv_ok(x, _) if {
	x[1] == ""
	x[2] == ""
}

_flow_recv_ok(x, c) if x[1] in c

_flow_recv_ok(x, c) if x[2] in c

# A text that is a constant: literals, numbers, UPPER_CASE constants, and
# names that C says are constant and were last defined above `line`.
_flow_sconst(text, line, C) if {
	b0 := regex.replace(_flow_blank(text), _flow_cast_re, " ")
	b := regex.replace(b0, `\.\s*(?:trim|strip|toUpperCase|toLowerCase|toString|intern|length)\s*\(\s*\)`, "")
	trim_space(b) != ""
	not regex.match(`[\[\]{}?;]`, b)
	not regex.match(`\.\s*[A-Za-z_$][\w$]*\s*\(`, b)
	not regex.match(`(?:^|[^=!<>])=(?:[^=]|$)`, b)
	every m in regex.find_all_string_submatch_n(`(?:^|[^\w.$])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)(\s*\()?`, b, -1) {
		m[2] == ""
		_flow_cname(m[1], line, C)
	}
}

_flow_cname(x, _, _) if x in {"true", "false", "null"}

_flow_cname(x, _, _) if regex.match(`(?:^|\.\s*)[A-Z][A-Z0-9_]*$`, x)

_flow_cname(x, _, _) if regex.match(`^File\s*\.\s*(?:separator|pathSeparator)$`, x)

_flow_cname(x, line, C) if C[x] < line

# ── Lists and maps used as value carriers ────────────────────────────────

_flow_coll_re := `\b([A-Za-z_]\w*)\s*=\s*new\s+(?:java\.util\.(?:concurrent\.)?)?(ArrayList|LinkedList|Vector|CopyOnWriteArrayList|HashMap|LinkedHashMap|TreeMap|Hashtable|ConcurrentHashMap)\s*(?:<[^>]*>)?\s*\(\s*\)`

# The [value text, line] stored at index/key `key` of local collection L when
# it is read on window line j, if every use of L before j is understood.
_flow_cget(ctx, lines, L, key, j) := e if {
	ds := [d |
		some d in ctx.defs
		d.v == L
		d.n < j
		regex.match(_flow_coll_re, lines[ctx.s + d.n])
	]
	count(ds) == 1
	_flow_single(ctx, ctx.defs, L)
	m := regex.find_all_string_submatch_n(_flow_coll_re, lines[ctx.s + ds[0].n], 1)
	m[0][1] == L
	kind := _flow_coll_kind(m[0][2])
	re := concat("", [`\b`, L, `\b`])
	refs := [k | some k in numbers.range(ds[0].n + 1, j - 1); k < j; k > ds[0].n; regex.match(re, ctx.b[k])]
	every k in refs {
		_flow_use_ok(ctx.b[k], L)
	}
	muts := [k | some k in refs; regex.match(concat("", [`\b`, L, `\s*\.\s*(?:add|put|remove|set|clear)\s*\(`]), ctx.b[k])]
	sts := {k: s | some k in muts; s := _flow_status(ctx, lines, k, j)}
	every k in muts {
		sts[k] != "cond"
	}
	ops := [o | some k in muts; sts[k] == "dom"; o := _flow_cop(kind, L, lines[ctx.s + k], ctx.s + k)]
	count(ops) == count([k | some k in muts; sts[k] == "dom"])
	e := _flow_cval(kind, ops, key)
}

_flow_coll_kind(t) := "map" if endswith(t, "Map")

_flow_coll_kind(t) := "map" if t == "Hashtable"

_flow_coll_kind(t) := "list" if {
	not endswith(t, "Map")
	t != "Hashtable"
}

# Every mention of L on the line is a call this analysis understands, and a
# mutating call is the whole statement.
_flow_use_ok(b, L) if {
	all := count(regex.find_n(concat("", [`\b`, L, `\b`]), b, -1))
	calls := count(regex.find_n(concat("", [`\b`, L, `\s*\.\s*(?:get|size|isEmpty|contains|containsKey|containsValue|add|put|remove|set|clear)\s*\(`]), b, -1))
	all == calls
	muts := count(regex.find_n(concat("", [`\b`, L, `\s*\.\s*(?:add|put|remove|set|clear)\s*\(`]), b, -1))
	_flow_mut_stmt(b, L, muts)
}

_flow_mut_stmt(_, _, 0)

_flow_mut_stmt(b, L, 1) if regex.match(concat("", [`^\s*`, L, `\s*\.\s*(?:add|put|remove|set|clear)\s*\(`]), b)

_flow_cop_re(L) := concat("", [`^\s*`, L, `\s*\.\s*(add|put|remove|set|clear)\s*\((.*)\)\s*;\s*(?://.*)?$`])

_flow_cop(kind, L, raw, line) := o if {
	m := regex.find_all_string_submatch_n(_flow_cop_re(L), raw, 1)
	count(m) > 0
	o := _flow_cop1(kind, m[0][1], m[0][2], line)
}

_flow_cop1("list", "add", a, line) := {"t": "add", "x": a, "k": line} if {
	ab := _flow_blank(a)
	not regex.match(`^(?:[^(),]|\((?:[^()]|\([^()]*\))*\))*,`, ab)
}

_flow_cop1("list", "add", a, line) := {"t": "ins", "i": to_number(m[0][1]), "x": m[0][2], "k": line} if {
	m := regex.find_all_string_submatch_n(`^\s*(\d+)\s*,\s*(.*)$`, a, 1)
	count(m) > 0
}

_flow_cop1("list", "set", a, line) := {"t": "set", "i": to_number(m[0][1]), "x": m[0][2], "k": line} if {
	m := regex.find_all_string_submatch_n(`^\s*(\d+)\s*,\s*(.*)$`, a, 1)
	count(m) > 0
}

_flow_cop1("list", "remove", a, _) := {"t": "rm", "i": to_number(trim_space(a))} if regex.match(`^\s*\d+\s*$`, a)

_flow_cop1(_, "clear", a, _) := {"t": "clear"} if trim_space(a) == ""

_flow_cop1("map", "put", a, line) := {"t": "put", "key": m[0][1], "x": m[0][2], "k": line} if {
	m := regex.find_all_string_submatch_n(`^\s*("(?:[^"\\]|\\.)*")\s*,\s*(.*)$`, a, 1)
	count(m) > 0
}

_flow_cop1("map", "remove", a, _) := {"t": "del", "key": trim_space(a)} if regex.match(`^\s*"(?:[^"\\]|\\.)*"\s*$`, a)

_flow_cval("map", ops, key) := [last.x, last.k] if {
	touch := [o | some o in ops; _flow_touches(o, key)]
	count(touch) > 0
	last := touch[count(touch) - 1]
	last.t == "put"
}

_flow_cval("list", ops, key) := [el[0], el[1]] if {
	count(ops) <= 10
	regex.match(`^\d+$`, key)
	s := _flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep(_flow_lstep([], ops, 0), ops, 1), ops, 2), ops, 3), ops, 4), ops, 5), ops, 6), ops, 7), ops, 8), ops, 9)
	el := s[to_number(key)]
}

_flow_touches(o, _) if o.t == "clear"

_flow_touches(o, key) if o.key == key

_flow_lstep(s, ops, k) := s if k >= count(ops)

_flow_lstep(s, ops, k) := _flow_lop(s, ops[k]) if k < count(ops)

_flow_lop(s, o) := array.concat(s, [[o.x, o.k]]) if o.t == "add"

_flow_lop(s, o) := array.concat(array.concat(array.slice(s, 0, o.i), [[o.x, o.k]]), array.slice(s, o.i, count(s))) if {
	o.t == "ins"
	o.i <= count(s)
}

_flow_lop(s, o) := array.concat(array.concat(array.slice(s, 0, o.i), [[o.x, o.k]]), array.slice(s, o.i + 1, count(s))) if {
	o.t == "set"
	o.i < count(s)
}

_flow_lop(s, o) := array.concat(array.slice(s, 0, o.i), array.slice(s, o.i + 1, count(s))) if {
	o.t == "rm"
	o.i < count(s)
}

_flow_lop(_, o) := [] if o.t == "clear"

# ── Same-file methods whose every return is constant ─────────────────────

_flow_called(ctx) := {m[1] |
	some b in ctx.b
	contains(b, "(")
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.$]|\.)\s*([a-z_]\w*)\s*\(`, b, -1)
	not m[1] in _flow_kw
}

_flow_const_methods(lines, names) := {nm |
	some nm in names
	re := concat("", [`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)*(?:<[^>]*>\s+)?([\w.$<>\[\]]+)\s+`, nm, `\s*\(`])
	decls := [k |
		some k, l in lines
		contains(l, nm)
		m := regex.find_all_string_submatch_n(re, l, 1)
		count(m) > 0
		not m[0][1] in _flow_kw
		not contains(l, ";")
	]
	count(decls) > 0
	every k in decls {
		_flow_method_const(lines, k)
	}
}

_flow_method_const(lines, k) if {
	end := min([count(lines) - 1, k + 150])
	dls := [_flow_delta(_flow_code(lines[x])) | some x in numbers.range(k, end)]
	pre := [sum(array.slice(dls, 0, p + 1)) | some p in numbers.range(0, count(dls) - 1)]
	f := min([p | some p, v in pre; v > 0])
	e := min([p | some p, v in pre; p > f; v <= 0])
	rets := [x | some x in numbers.range(k + f, k + e); regex.match(`(?:^|[^\w$])return\b`, _flow_code(lines[x]))]
	count(rets) > 0
	every x in rets {
		_flow_ret_const(lines, x)
	}
}

_flow_ret_const(lines, x) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?return\s+((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^;"'])+);`, lines[x], 1)
	count(m) > 0
	ctx := _flow_ctx(lines, x)
	M := {"m": set(), "c": set()}
	C := _flow_core(ctx, lines, M)
	every q in _flow_reqs_of(ctx, lines, m[0][1], x, ctx.t, M) {
		_flow_sconst(q[0], q[1], C)
	}
}

# ── Constants at a line ──────────────────────────────────────────────────

_flow_core(ctx, lines, M) := c4 if {
	vr := _flow_var_reqs(ctx, lines, M)
	c1 := _flow_round(vr, {})
	c2 := _flow_round(vr, c1)
	c3 := _flow_round(vr, c2)
	c4 := _flow_round(vr, c3)
}

_flow_round(vr, C) := {v: e.ln |
	some v, e in vr
	every q in e.rq {
		_flow_sconst(q[0], q[1], C)
	}
}

_flow_var_reqs(ctx, lines, M) := {v: e |
	some v in {d.v | some d in ctx.defs}
	not _flow_mutated(ctx, ctx.defs, v)
	st := [[d, s] | some d in ctx.defs; d.v == v; s := _flow_status(ctx, lines, d.n, ctx.t)]
	live := [x | some x in st; x[1] != "dead"]
	doms := [x[0].n | some x in live; x[1] == "dom"; x[0].op == "="]
	count(doms) > 0
	b := max(doms)
	after := [x[0] | some x in live; x[0].n >= b]
	rq := [q |
		some d in after
		some q in _flow_def_reqs(ctx, lines, d, M)
	]
	e := {"ln": ctx.s + max([d.n | some d in after]), "rq": rq}
}

_flow_def_reqs(ctx, lines, d, M) := array.concat(q, _flow_def_mentions(ctx, d.v, r)) if {
	r0 := _flow_rhs(lines, ctx.s + d.n, d.v)
	r := object.get(object.get(M, "x", {}), sprintf("%d:%s", [ctx.s + d.n, d.v]), r0)
	q := _flow_reqs_of(ctx, lines, r, ctx.s + d.n, d.n, M)
} else := [["?", ctx.s + d.n]]

# A value an inert call produced is not constant if the local is then fed
# run-time data through a call on it (sb.append(tainted)).
_flow_def_mentions(ctx, v, r) := _flow_call_mentions(ctx, v) if count(_flow_inert_hits(r)) > 0

_flow_def_mentions(_, _, r) := [] if count(_flow_inert_hits(r)) == 0

flow_consts(lines, i) := C if {
	ctx := _flow_ctx(lines, i)
	classes := {m[1] |
		some l in lines
		contains(l, " class ")
		some m in regex.find_all_string_submatch_n(`\b(?:class|enum|record|interface)\s+([A-Z]\w*)`, l, -1)
	}
	M0 := {"m": _flow_const_methods(lines, _flow_called(ctx)), "c": classes}
	M := object.union(M0, {"x": _flow_xtable(ctx, lines, M0)})
	C := _flow_core(ctx, lines, M)
} else := {}

# text with the names C holds as constants (last defined above `line`)
# replaced by "", outside string literals, and inert calls (see above) whose
# arguments and receiver are constants replaced by "".
flow_fold(text, line, C) := _flow_fold_names(f4, line, C) if {
	f1 := _flow_fold_inert(text, line, C)
	f2 := _flow_fold_inert(f1, line, C)
	f3 := _flow_fold_inert(f2, line, C)
	f4 := _flow_fold_inert(f3, line, C)
}

_flow_fold_inert(text, _, _) := text if not contains(text, "(")

_flow_fold_inert(text, line, C) := strings.replace_n({h.all: `""` | some h in hs}, text) if {
	contains(text, "(")
	hs := [h |
		some h in _flow_inert_hits(text)
		_flow_fold_ok(h, line, C)
	]
	count(hs) > 0
}

_flow_fold_inert(text, line, C) := text if {
	contains(text, "(")
	count([h | some h in _flow_inert_hits(text); _flow_fold_ok(h, line, C)]) == 0
}

_flow_fold_ok(h, line, C) if {
	_flow_fold_recv_ok(h, line, C)
	_flow_fold_args_ok(h, line, C)
}

_flow_fold_recv_ok(h, _, _) if h.kind == "type"

_flow_fold_recv_ok(h, line, C) if {
	h.kind == "local"
	C[h.recv] < line
}

_flow_fold_args_ok(h, _, _) if trim_space(h.args) == ""

_flow_fold_args_ok(h, line, C) if {
	trim_space(h.args) != ""
	_flow_sconst(h.args, line, C)
}

_flow_fold_names(text, line, C) := text if count([v | some v, l in C; l < line]) == 0

_flow_fold_names(text, line, C) := concat("", [_flow_fold_tok(tok, re) |
	some tok in regex.find_n(`"(?:[^"\\]|\\.)*"|[^"]+|"`, text, -1)
]) if {
	ns := [v | some v, l in C; l < line]
	count(ns) > 0
	re := concat("", [`(^|[^\w.$])(?:`, concat("|", ns), `)\b`])
}

_flow_fold_tok(tok, _) := tok if startswith(tok, "\"")

_flow_fold_tok(tok, re) := regex.replace(tok, re, `${1}""`) if not startswith(tok, "\"")

# ── Taint within the method ──────────────────────────────────────────────

_flow_carrier_re := `^\s*(?:\}\s*)?(?:else\s+)?([A-Za-z_]\w*)\s*\.\s*(?:add|addAll|put|putAll|set|push|offer|append|insert|addElement)\s*\((.*)$`

flow_tainted(lines, i, seeds, san) := t if {
	ctx := _flow_ctx(lines, i)
	C := flow_consts(lines, i)
	asg := array.concat([[d.v, _flow_blank(r)] |
		some d in ctx.defs
		not C[d.v]
		_flow_status(ctx, lines, d.n, ctx.t) != "dead"
		r0 := _flow_rhs_or_line(lines, ctx.s + d.n, d.v)
		not regex.match(san, r0)
		r := _flow_xrw(lines, ctx.s + d.n, r0)
	], [[m[0][1], m[0][2]] |
		some n in numbers.range(0, ctx.t - 1)
		n < ctx.t
		contains(ctx.b[n], ".")
		m := regex.find_all_string_submatch_n(_flow_carrier_re, ctx.b[n], 1)
		count(m) > 0
		not C[m[0][1]]
		_flow_status(ctx, lines, n, ctx.t) != "dead"
		not regex.match(san, lines[ctx.s + n])
	])
	fe := [[m[1], m[2]] |
		some b in ctx.b
		contains(b, "for")
		some m in regex.find_all_string_submatch_n(`\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)`, b, 1)
	]
	t0 := {v | some v in seeds; not C[v]}
	h5 := _flow_hop5(asg, fe, t0)
	t := _flow_hop5(asg, fe, h5)
}

_flow_hop5(asg, fe, t) := _flow_hop(asg, fe, _flow_hop(asg, fe, _flow_hop(asg, fe, _flow_hop(asg, fe, _flow_hop(asg, fe, t)))))

_flow_hop(_, _, t) := t if count(t) == 0

_flow_hop(asg, fe, t) := (t | {a[0] | some a in asg; regex.match(re, a[1])}) | {p[0] | some p in fe; p[1] in t} if {
	count(t) > 0
	re := concat("", [`(?:^|[^\w.$])(?:`, concat("|", t), `)\b`])
}

_flow_rhs_or_line(lines, j, v) := r if r := _flow_rhs(lines, j, v)
else := lines[j]

# Recall first: a line the analysis cannot window is left to the rule.
flow_reaches(lines, i, _, _, _) if not _flow_ctx(lines, i)

flow_reaches(lines, i, text, seeds, san) if {
	t := flow_tainted(lines, i, seeds, san)
	count(t) > 0
	regex.match(concat("", [`(?:^|[^\w.$])(?:`, concat("|", t), `)\b`]), _flow_blank(_flow_xrw(lines, i, text)))
}

_flow_delta(b) := count(regex.find_n(`\{`, b, -1)) - count(regex.find_n(`\}`, b, -1))

# The first line of the method body enclosing line i, at most 120 lines up:
# the look-back bound for an in-method analysis.
flow_method_start(lines, i) := _flow_start(lines, i) if i > 0
else := 0

# Collections and builders in the method that are handed a value matching
# `src_re` directly (list.add(request.getParameter("x"))): seeds for
# flow_tainted, since no assignment names them.
flow_carrier_seeds(lines, i, src_re) := {m[0][1] |
	s := flow_method_start(lines, i)
	some k in numbers.range(s, i - 1)
	k < i
	k >= s
	contains(lines[k], ".")
	not is_comment_line(lines[k])
	m := regex.find_all_string_submatch_n(_flow_carrier_re, lines[k], 1)
	count(m) > 0
	regex.match(src_re, m[0][2])
}

# ── Cross-file method summaries (flow_x*) ────────────────────────────────
# A call into another class of the project is read from that class's own
# source, not guessed at. Every Java file of the project is visible to a rule
# in input.file_contents, so a call `obj.m(args)`, `Cls.m(args)` or
# `new Cls(args).m(args)` is resolved to the method(s) that can run:
#
#   - the class is found by the simple name of the declared type of `obj`
#     (a local, a parameter, or the `new Cls(...)` it was assigned from) or by
#     the static class name; a class declared in the file itself wins, and a
#     simple name declared by two files is ambiguous, so it is not resolved;
#   - a value of an interface or base class type runs the method of any
#     class that extends or implements it (two levels of the project's own
#     hierarchy), and an anonymous subclass makes the type unresolvable;
#   - the method is read (at most 60 lines, overloads told apart by arity) as
#     one of three summaries: const (every return is a constant, an
#     UPPER_CASE name or a constant the callee itself holds), pass (every
#     return is constant once the parameters, and the fields a single
#     constructor stores from its own parameters, are taken as constants:
#     the value depends on exactly the parameters and constructor arguments
#     the analysis proves it depends on) or opaque (anything else: a source
#     read, a field that is not constant, a call it cannot see through, more
#     than 8 inputs). Overrides and overloads are joined: const + pass is
#     pass, anything + opaque is opaque.
#
# The call is then replaced in the text being asked about: const by "", pass
# by the actual argument(s) (and, for a getter of constructor-stored state,
# the constructor argument of the `new Cls(...)` the receiver was assigned
# from, when that is the only assignment to it), opaque or unresolved is left
# as written, so it stays tainted exactly as before. A callee is not resolved
# again from inside its own body (one level of calls deep).

_flow_A := `(?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*`

_flow_xnew_re := concat("", [`(^|[^\w.$])new\s+(?:[a-z]\w*\s*\.\s*)*([A-Z]\w*)\s*(?:<[^()]*>)?\s*\((`, _flow_A, `)\)\s*\.\s*([a-z_]\w*)\s*\((`, _flow_A, `)\)`])

_flow_xcall_re := concat("", [`(^|[^\w.$])((?:[a-z]\w*\s*\.\s*)*)([A-Za-z_]\w*)\s*\.\s*([a-z_]\w*)\s*\((`, _flow_A, `)\)`])

# Top-level comma separated pieces of an argument list.
_flow_pieces(s) := [] if trim_space(s) == ""

_flow_pieces(s) := [trim_space(m[0]) |
	trim_space(s) != ""
	some m in regex.find_all_string_submatch_n(`(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\{[^{}]*\}|[^,"'(){}])+`, s, -1)
]

# Parameter names of a declaration's parameter list, in order.
_flow_xpnames(s) := [] if trim_space(s) == ""

_flow_xpnames(s) := [m2[0][1] |
	trim_space(s) != ""
	some m in regex.find_all_string_submatch_n(`(?:<(?:[^<>]|<[^<>]*>)*>|[^,<>])+`, s, -1)
	m2 := regex.find_all_string_submatch_n(`(\w+)\s*(?:\[\s*\]\s*)*$`, trim_space(m[0]), 1)
]

# ── The project's classes ───────────────────────────────────────────────

# class simple name -> the files that declare it.
_flow_jdecls[name] contains path if {
	some path, content in input.file_contents
	endswith(path, ".java")
	some m in regex.find_all_string_submatch_n(`\b(?:class|interface|enum|record)\s+([A-Z]\w*)`, content, -1)
	name := m[1]
}

# The whole extent as one value, evaluated once: a lookup by name on the partial
# rule above would re-run its body over every file.
_flow_jdecl_map := _flow_jdecls

# Names of the methods the project declares (a call to any other name cannot
# resolve, so it is rejected before any class is looked up).
_flow_jmeth_names := {m[1] |
	some path, content in input.file_contents
	endswith(path, ".java")
	some m in regex.find_all_string_submatch_n(`(?m)^[ \t]*(?:@\w+(?:\([^)]*\))?[ \t]+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default)[ \t]+)*(?:<[^>]*>[ \t]+)?[\w.$<>\[\]]+[ \t]+([a-z_]\w*)[ \t]*\(`, content, -1)
}

# [parent, child] for every `class C extends/implements P` (and interface
# extends) in the project, and [P, "?"] for an anonymous subclass of P.
_flow_jsub_pairs contains [parent, child] if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\b(?:extends|implements)\b`, content)
	some m in regex.find_all_string_submatch_n(`\b(?:class|interface|enum|record)\s+([A-Z]\w*)\b[^{;]*?\b(?:extends|implements)\b([^{;]*)\{`, content, -1)
	child := m[1]
	some p in regex.find_all_string_submatch_n(`[A-Z]\w*`, m[2], -1)
	parent := p[0]
}

_flow_jsub_pairs contains [parent, "?"] if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\)\s*\{`, content)
	some m in regex.find_all_string_submatch_n(`\bnew\s+(?:[a-z]\w*\s*\.\s*)*([A-Z]\w*)\s*(?:<[^()]*>)?\s*\([^;{}]*\)\s*\{`, content, -1)
	parent := m[1]
}

_flow_jf(path) := split(input.file_contents[path], "\n")

# The type and the project classes below it (two levels); undefined when an
# anonymous subclass could be any of them.
_flow_jparents contains p if some [p, _] in _flow_jsub_pairs

_flow_xtypes[t] := s if {
	some t in _flow_jparents
	s1 := {c | some [p, c] in _flow_jsub_pairs; p == t}
	s2 := {c | some [p, c] in _flow_jsub_pairs; p in s1}
	s := (s1 | s2) | {t}
	not "?" in s
}

_flow_xtypeset(t) := {t} if not t in _flow_jparents

_flow_xtypeset(t) := _flow_xtypes[t] if t in _flow_jparents

_flow_xdecl_re(name) := concat("", [`\b(?:class|interface|enum|record)\s+`, name, `\b`])

_flow_xlocal(lines, name) := [k |
	some k, l in lines
	contains(l, name)
	regex.match(_flow_xdecl_re(name), l)
	not is_comment_line(l)
]

_flow_xkind(l) := "interface" if regex.match(`\binterface\b`, l)

_flow_xkind(l) := "abstract" if {
	not regex.match(`\binterface\b`, l)
	regex.match(`\babstract\b`, l)
}

_flow_xkind(l) := "class" if {
	not regex.match(`\binterface\b`, l)
	not regex.match(`\babstract\b`, l)
}

# The file that declares class `name`: the call site's own file if it does
# (a nested class shadows), otherwise the one file of the project that does.
_flow_xdecl(lines, name) := {"lines": lines, "kind": _flow_xkind(lines[ks[0]]), "head": lines[ks[0]]} if {
	ks := _flow_xlocal(lines, name)
	count(ks) == 1
} else := {"lines": dl, "kind": _flow_xkind(dl[ks[0]]), "head": dl[ks[0]]} if {
	count(_flow_xlocal(lines, name)) == 0
	ps := _flow_jdecl_map[name]
	count(ps) == 1
	some p in ps
	dl := _flow_jf(p)
	ks := _flow_xlocal(dl, name)
	count(ks) == 1
}

_flow_xsup(head) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bextends\s+(?:[a-z]\w*\s*\.\s*)*([A-Z]\w*)`, head, 1)
	count(m) > 0
	not regex.match(`\binterface\b`, head)
}

# ── Methods ─────────────────────────────────────────────────────────────

_flow_xmdecl_re(nm) := concat("", [`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*(?:<[^>]*>\s+)?([\w.$<>\[\]]+)\s+`, nm, `\s*\(`])

# Declarations of method nm that have a body: line and parameter list.
_flow_xmeths(dlines, nm) := [{"k": k, "params": hm[0][1]} |
	some k, l in dlines
	contains(l, nm)
	m := regex.find_all_string_submatch_n(_flow_xmdecl_re(nm), l, 1)
	count(m) > 0
	not m[0][1] in _flow_kw
	not is_comment_line(l)
	t := concat(" ", array.slice(dlines, k, k + 4))
	hm := regex.find_all_string_submatch_n(concat("", [`\b`, nm, `\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+?)?\s*\{`]), t, 1)
	count(hm) > 0
]

# Every declaration of that name, with or without a body (abstract ones too):
# a varargs overload makes the arity ambiguous.
_flow_xvarargs(dlines, nm) if {
	some l in dlines
	contains(l, "...")
	contains(l, nm)
	regex.match(concat("", [`\b`, nm, `\s*\([^)]*\.\.\.`]), l)
}

_flow_xctor_re(cn) := concat("", [`^\s*(?:(?:public|protected|private)\s+)?`, cn, `\s*\(`])

_flow_xctors(dlines, cn) := [{"k": k, "params": hm[0][1]} |
	some k, l in dlines
	contains(l, cn)
	regex.match(_flow_xctor_re(cn), l)
	not is_comment_line(l)
	t := concat(" ", array.slice(dlines, k, k + 4))
	hm := regex.find_all_string_submatch_n(concat("", [`\b`, cn, `\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+?)?\s*\{`]), t, 1)
	count(hm) > 0
]

# The method (or constructor) starting at line k, up to its closing brace
# (at most 60 lines). A one-line `T m() { return x; }` becomes three lines.
_flow_xbody(dlines, k) := b if {
	end := min([count(dlines) - 1, k + 60])
	dls := [_flow_delta(_flow_code(dlines[x])) | some x in numbers.range(k, end)]
	pre := [sum(array.slice(dls, 0, p + 1)) | some p in numbers.range(0, count(dls) - 1)]
	f := min([p | some p, v in pre; v > 0])
	e := min([p | some p, v in pre; p >= f; v <= 0])
	b := array.slice(dlines, k, k + e + 1)
	count(b) >= 2
} else := ["{", m[0][1], "}"] if {
	_flow_delta(_flow_code(dlines[k])) == 0
	m := regex.find_all_string_submatch_n(`\{\s*(return\b[^{}]*;)\s*\}\s*$`, dlines[k], 1)
	count(m) > 0
}

_flow_xret_re := `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?return\s+((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^;"'])+);`

_flow_xrets(body) := [x | some x in numbers.range(1, count(body) - 1); regex.match(`(?:^|[^\w$])return\b`, _flow_code(body[x]))]

# The constants of a method body when the names in P are taken as constants.
_flow_core_p(ctx, lines, M, P) := c4 if {
	vr := _flow_var_reqs(ctx, lines, M)
	c1 := object.union(_flow_round(vr, P), P)
	c2 := object.union(_flow_round(vr, c1), P)
	c3 := object.union(_flow_round(vr, c2), P)
	c4 := object.union(_flow_round(vr, c3), P)
}

_flow_xret_ok(body, M, P, x) if {
	m := regex.find_all_string_submatch_n(_flow_xret_re, body[x], 1)
	count(m) > 0
	ctx := _flow_ctx(body, x)
	C := _flow_core_p(ctx, body, M, P)
	every q in _flow_reqs_of(ctx, body, m[0][1], x, ctx.t, M) {
		_flow_sconst(q[0], q[1], C)
	}
}

# Every return of the body is a constant given P.
_flow_xok(body, M, P) if {
	rets := _flow_xrets(body)
	count(rets) > 0
	every x in rets {
		_flow_xret_ok(body, M, P, x)
	}
}

_flow_xclasses(dlines) := {m[1] |
	some l in dlines
	contains(l, " class ")
	some m in regex.find_all_string_submatch_n(`\b(?:class|enum|record|interface)\s+([A-Z]\w*)`, l, -1)
}

_flow_xcalled(body) := {m[1] |
	some b in body
	contains(b, "(")
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.$]|\.)\s*([a-z_]\w*)\s*\(`, _flow_code(b), -1)
	not m[1] in _flow_kw
}

# Fields of class cn that the analysis may rely on, read from the file that
# declares it: kf {field: constructor parameter index} for the fields the one
# constructor stores from its own parameter and nothing else in the file ever
# assigns; cf, the fields initialised to a literal and never assigned again.
_flow_xfields(dlines, cn) := {"kf": _flow_xkf(dlines, _flow_xctors(dlines, cn)), "cf": _flow_xcf(dlines)}

_flow_xassign_re(f) := concat("", [`(?:^|[^\w$])(?:this\s*\.\s*)?`, f, `\s*(?:[-+*/%&|^]|<<|>>>?)?=(?:[^=]|$)|(?:^|[^\w$])`, f, `\s*(?:\+\+|--)|(?:\+\+|--)\s*`, f, `\b`])

_flow_xin(k, k0, n) if {
	k >= k0
	k < k0 + n
}

_flow_xother_assign(dlines, f, k0, n) if {
	some k, l in dlines
	contains(l, f)
	not _flow_xin(k, k0, n)
	regex.match(_flow_xassign_re(f), _flow_code(l))
}

_flow_xprivate(dlines, f) if {
	some l in dlines
	contains(l, f)
	regex.match(concat("", [`^\s*private\s+[^=;(]*\b`, f, `\s*[=;]`]), l)
}

_flow_xstore_ok(m, _) if m[0][1] != ""

_flow_xstore_ok(m, ps) if {
	m[0][1] == ""
	not m[0][2] in ps
}

_flow_xkf(dlines, ctors) := kf if {
	count(ctors) == 1
	ct := ctors[0]
	ps := _flow_xpnames(ct.params)
	cb := _flow_xbody(dlines, ct.k)
	kf := {f: idx |
		some bl in cb
		m := regex.find_all_string_submatch_n(`^\s*(this\s*\.\s*)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;`, bl, 1)
		count(m) > 0
		f := m[0][2]
		_flow_xstore_ok(m, ps)
		some idx, pn in ps
		pn == m[0][3]
		count([1 | some b2 in cb; regex.match(_flow_xassign_re(f), _flow_code(b2))]) == 1
		_flow_xprivate(dlines, f)
		not _flow_xother_assign(dlines, f, ct.k, count(cb))
	}
} else := {}

_flow_xcf(dlines) := {f |
	some l in dlines
	contains(l, "=")
	m := regex.find_all_string_submatch_n(`^\s*private\s+(?:(?:static|final|volatile|transient)\s+)*[\w.$<>\[\]]+\s+([A-Za-z_]\w*)\s*=\s*(?:"(?:[^"\\]|\\.)*"|-?\d[\w.]*|true|false|null)\s*;`, l, 1)
	count(m) > 0
	f := m[0][1]
	count([1 | some l2 in dlines; contains(l2, f); regex.match(_flow_xassign_re(f), _flow_code(l2))]) == 1
}

# ── Summaries ───────────────────────────────────────────────────────────

_flow_opaque := {"k": "opaque", "p": [], "c": []}

# The summary of one method: const, pass (with the parameter and constructor
# argument indexes the value depends on) or opaque.
_flow_xmsum(dlines, md, f) := r if {
	body := _flow_xbody(dlines, md.k)
	M := {"m": _flow_const_methods(dlines, _flow_xcalled(body)), "c": _flow_xclasses(dlines), "x": {}}
	P0 := {c: -1 | some c in f.cf}
	pn := _flow_xpnames(md.params)
	kfs := [k | some k, _ in f.kf; not k in pn]
	r := _flow_xclassify(body, M, P0, pn, kfs, f.kf)
} else := _flow_opaque


_flow_xclassify(body, M, P0, pn, kfs, kf) := {"k": "const", "p": [], "c": []} if {
	_flow_xok(body, M, P0)
} else := {"k": "pass", "p": pdeps, "c": cdeps} if {
	count(pn) + count(kfs) <= 8
	Pall := object.union(object.union(P0, {n: -1 | some n in pn}), {k: -1 | some k in kfs})
	_flow_xok(body, M, Pall)
	pdeps := [i | some i, n in pn; not _flow_xok(body, M, object.remove(Pall, [n]))]
	cdeps := [kf[k] | some k in kfs; not _flow_xok(body, M, object.remove(Pall, [k]))]
} else := _flow_opaque

_flow_xjoin(sums) := _flow_opaque if {
	some s in sums
	s.k == "opaque"
} else := {"k": "const", "p": [], "c": []} if {
	every s in sums {
		s.k == "const"
	}
} else := {"k": "pass", "p": sort({i | some s in sums; some i in s.p}), "c": sort({i | some s in sums; some i in s.c})}

# What method nm of arity n declared by class cn (in dlines) summarises to;
# undefined when cn's file has no such method.
_flow_xcsum(dlines, _, nm, _) := _flow_opaque if _flow_xvarargs(dlines, nm)

_flow_xcsum(dlines, cn, nm, n) := j if {
	not _flow_xvarargs(dlines, nm)
	ms := [md | some md in _flow_xmeths(dlines, nm); count(_flow_xpnames(md.params)) == n]
	count(ms) > 0
	f := _flow_xfields(dlines, cn)
	j := _flow_xjoin([_flow_xmsum(dlines, md, f) | some md in ms])
}

_flow_xown(lines, c, nm, n) := _flow_xcsum(d.lines, c, nm, n) if d := _flow_xdecl(lines, c)

# The method of class c, or of the closest of its three project superclasses
# that declares it.
_flow_xmember(lines, c, nm, n) := s if {
	s := _flow_xown(lines, c, nm, n)
} else := s if {
	d := _flow_xdecl(lines, c)
	p1 := _flow_xsup(d.head)
	s := _flow_xown(d.lines, p1, nm, n)
} else := s if {
	d := _flow_xdecl(lines, c)
	p1 := _flow_xsup(d.head)
	d1 := _flow_xdecl(d.lines, p1)
	p2 := _flow_xsup(d1.head)
	s := _flow_xown(d1.lines, p2, nm, n)
} else := s if {
	d := _flow_xdecl(lines, c)
	p1 := _flow_xsup(d.head)
	d1 := _flow_xdecl(d.lines, p1)
	p2 := _flow_xsup(d1.head)
	d2 := _flow_xdecl(d1.lines, p2)
	p3 := _flow_xsup(d2.head)
	s := _flow_xown(d2.lines, p3, nm, n)
}

# Class c as a call target: its summary, "none" for an interface or abstract
# class that only declares the method, opaque for a class that does not
# declare it (it comes from outside the project), undefined for an unknown
# class.
_flow_xcls(lines, c, nm, n) := s if {
	s := _flow_xmember(lines, c, nm, n)
} else := {"k": "none"} if {
	d := _flow_xdecl(lines, c)
	d.kind in {"interface", "abstract"}
} else := _flow_opaque if _flow_xdecl(lines, c)

_flow_xcls_top(lines, c, nm, n) := _flow_xcls(lines, c, nm, n)

_flow_xwrap(t) := trim_space(t) if regex.match(`^\s*(?:[A-Za-z_][\w.]*|"(?:[^"\\]|\\.)*"|\d+)\s*$`, t)

_flow_xwrap(t) := concat("", ["(", t, ")"]) if not regex.match(`^\s*(?:[A-Za-z_][\w.]*|"(?:[^"\\]|\\.)*"|\d+)\s*$`, t)

_flow_xrepl(j, _, _, _) := `""` if j.k == "const"

_flow_xrepl(j, ps, ctor, recv) := r if {
	j.k == "pass"
	pt := [ps[i] | some i in j.p]
	count(pt) == count(j.p)
	ct := [ctor[i] | some i in j.c]
	count(ct) == count(j.c)
	# The receiver travels with the constructor arguments it was built from, so
	# a receiver the caller already treats as run-time data stays that.
	rt := [recv | count(j.c) > 0; recv != ""]
	ts := array.concat(array.concat(pt, ct), rt)
	r := _flow_xjoin_txt(ts)
}

_flow_xjoin_txt(ts) := `""` if count(ts) == 0

_flow_xjoin_txt(ts) := _flow_xwrap(ts[0]) if count(ts) == 1

_flow_xjoin_txt(ts) := concat("", ["(", concat(" + ", ts), ")"]) if count(ts) > 1

# The text a call to method nm(args) on any of `classes` is replaced by.
_flow_xapply(lines, classes, ctor, recv, nm, args) := repl if {
	ps := _flow_pieces(args)
	sums := [s | some c in classes; s := _flow_xcls_top(lines, c, nm, count(ps))]
	count(sums) == count(classes)
	real := [s | some s in sums; s.k != "none"]
	count(real) > 0
	repl := _flow_xrepl(_flow_xjoin(real), ps, ctor, recv)
}

# ── Call sites ──────────────────────────────────────────────────────────

# The code of the enclosing method (signature included) above line j.
_flow_xwin(lines, j) := concat(" ", [_flow_code(lines[k]) | some k in span(max([0, flow_method_start(lines, j) - 1]), j - 1)])

# The method above line j and up to 80 lines below it.
_flow_xwin_all(lines, j) := concat(" ", [_flow_code(lines[k]) | some k in span(max([0, flow_method_start(lines, j) - 1]), min([count(lines) - 1, j + 80]))])

# The classes a local can hold and, when it was assigned once, from a
# `new Cls(args)`, that class alone with its constructor arguments.
_flow_xrecv(lines, j, recv) := {"classes": {nb[0][1]}, "ctor": _flow_pieces(nb[0][2])} if {
	w := _flow_xwin(lines, j)
	nb := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])`, recv, `\s*=\s*new\s+(?:[a-z]\w*\s*\.\s*)*([A-Z]\w*)\s*(?:<[^()]*>)?\s*\((`, _flow_A, `)\)\s*;`]), w, -1)
	count(nb) == 1
	# A second assignment further down (a loop) would make the exact class wrong.
	wa := _flow_xwin_all(lines, j)
	count(regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])`, recv, `\s*=(?:[^=]|$)`]), wa, -1)) == 1
} else := {"classes": ts, "ctor": null} if {
	w := _flow_xwin(lines, j)
	types := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.$])(?:final\s+)?(?:[a-z]\w*\s*\.\s*)*([A-Z]\w*)\s*(?:<[^;=()]*>)?\s+`, recv, `\s*(?:=|;|,|\)|:)`]), w, -1)}
	count(types) == 1
	some t in types
	ts := _flow_xtypeset(t)
}

_flow_xcall(lines, _, m) := _flow_xapply(lines, {m[3]}, null, "", m[4], m[5]) if {
	regex.match(`^[A-Z]`, m[3])
	m[4] in _flow_jmeth_names
}

_flow_xcall(lines, j, m) := _flow_xapply(lines, rv.classes, rv.ctor, m[3], m[4], m[5]) if {
	regex.match(`^[a-z_]`, m[3])
	m[4] in _flow_jmeth_names
	m[2] == ""
	not m[3] in _flow_kw
	rv := _flow_xrecv(lines, j, m[3])
}

_flow_xnew(lines, text) := strings.replace_n(rep, text) if {
	rep := {all: r |
		some m in regex.find_all_string_submatch_n(_flow_xnew_re, text, -1)
		m[4] in _flow_jmeth_names
		all := substring(m[0], count(m[1]), -1)
		r := _flow_xapply(lines, {m[2]}, _flow_pieces(m[3]), "", m[4], m[5])
	}
	count(rep) > 0
} else := text

_flow_xstat(lines, j, text) := strings.replace_n(rep, text) if {
	rep := {all: r |
		some m in regex.find_all_string_submatch_n(_flow_xcall_re, text, -1)
		all := substring(m[0], count(m[1]), -1)
		r := _flow_xcall(lines, j, m)
	}
	count(rep) > 0
} else := text

# An unqualified call to a method of this file (a private helper, a static
# method), summarised the same way; fields other than literal constants are
# not tracked.
_flow_xlocal_re := concat("", [`(^|[^\w.$])([a-z_]\w*)\s*\((`, _flow_A, `)\)`])

_flow_xlocalcall(lines, m) := repl if {
	m[2] in _flow_jmeth_names
	not m[2] in _flow_kw
	ps := _flow_pieces(m[3])
	not _flow_xvarargs(lines, m[2])
	ms := [md | some md in _flow_xmeths(lines, m[2]); count(_flow_xpnames(md.params)) == count(ps)]
	count(ms) > 0
	# A method a subclass elsewhere could override is not read.
	every md in ms {
		regex.match(`\b(?:private|static)\b`, lines[md.k])
	}
	f := {"kf": {}, "cf": _flow_xcf(lines)}
	repl := _flow_xrepl(_flow_xjoin([_flow_xmsum(lines, md, f) | some md in ms]), ps, null, "")
}

_flow_xloc(lines, text) := strings.replace_n(rep, text) if {
	rep := {all: r |
		some m in regex.find_all_string_submatch_n(_flow_xlocal_re, text, -1)
		all := substring(m[0], count(m[1]), -1)
		r := _flow_xlocalcall(lines, m)
	}
	count(rep) > 0
} else := text

_flow_xround(lines, j, text) := _flow_xloc(lines, _flow_xstat(lines, j, _flow_xnew(lines, text)))

# The text with every call into another class of the project that resolves to
# a constant or to a function of its arguments replaced (see above). `j` is
# the line the text is on: receivers are looked up in the method above it.
_flow_xrw(lines, j, text) := _flow_xround(lines, j, _flow_xround(lines, j, _flow_xround(lines, j, text))) if {
	regex.match(`[a-z_]\w*\s*\(`, text)
} else := text

# {"line:name": rewritten right-hand side} for the definitions in the window
# whose right-hand side calls into another class.
_flow_xtable(ctx, lines, M0) := {k: rx |
	some d in ctx.defs
	j := ctx.s + d.n
	r := _flow_rhs(lines, j, d.v)
	r2 := _flow_drop_calls(r, M0)
	rx := _flow_xrw(lines, j, r2)
	rx != r2
	k := sprintf("%d:%s", [j, d.v])
}

# `text` on line i with the calls into other classes of the project that
# resolve (const -> "", pass -> the argument) replaced; use it before
# flow_fold / flow_reaches on text that contains such a call.
flow_xrw(lines, i, text) := _flow_xrw(lines, i, text)

# ── Python in-function flow (flow_py_*) ──────────────────────────────────
# The same reading of the enclosing function as flow_* above, for Python,
# where blocks are indentation rather than braces. Bounded to the enclosing
# def and at most 120 lines above the line asked about:
#
#   flow_py_consts(lines, i)   locals that provably hold a constant at line i:
#                              every definition that can reach i (after the
#                              last one that runs on every path) is a literal
#                              or constant expression, after folding if/elif/
#                              else and conditional expressions whose condition
#                              is constant (integer literals and int locals
#                              assigned once, or 'lit' [not] in a string local),
#                              a match on a constant, a list, dict or
#                              ConfigParser read back at a constant index or
#                              key, a copy (`b = a`) of what a held at that
#                              line, and a call to a function of this file
#                              whose every return is constant. Object
#                              {name: line}. A name rebound any other way
#                              (augmented, tuple, for/with/except target,
#                              walrus, global, later in an enclosing loop) is
#                              never constant; a nested def is its own scope.
#   flow_py_fold(text, line, C) the text with those names (defined above
#                              `line`) replaced: "" in code, 0 inside an
#                              f-string placeholder.
#
# Anything the helpers cannot resolve is not constant.

_flow_py_kw := {"if", "elif", "else", "for", "while", "with", "try", "except", "finally", "match", "case", "def", "class", "return", "lambda", "not", "and", "or", "in", "is", "del", "global", "nonlocal", "async", "await", "yield", "pass", "break", "continue", "raise", "import", "from", "assert", "True", "False", "None", "print", "self"}

_flow_py_tok_re := `[fFrRbBuU]{0,2}"(?:[^"\\]|\\.)*"|[fFrRbBuU]{0,2}'(?:[^'\\]|\\.)*'|#.*|\w+|[^\w"'#]+|["']`

_flow_py_str_re := `^[fFrRbBuU]{0,2}(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')$`

_flow_py_tokens(l) := regex.find_n(_flow_py_tok_re, l, -1)

_flow_py_is_f(tok) if regex.match(`^(?:[fF][rR]?|[rR][fF])["']`, tok)

# Code view of a text: comments dropped, plain strings "", an f-string ""
# followed by its placeholders in parentheses ("?" when they do not parse),
# an unmatched quote "?".
_flow_py_code(l) := concat("", [_flow_py_ctok(t) | some t in _flow_py_tokens(l)])

_flow_py_ctok(t) := "" if startswith(t, "#")
else := "?" if {
	regex.match(`^["']$`, t)
} else := _flow_py_ftok(t) if {
	regex.match(_flow_py_str_re, t)
	_flow_py_is_f(t)
} else := `""` if {
	regex.match(_flow_py_str_re, t)
} else := t

_flow_py_ftok(t) := concat("", [`""`, concat("", [concat("", [" (", regex.replace(p[1], `[!:][^{}]*$`, ""), ")"]) | some p in ps])]) if {
	inner := strings.replace_n({"{{": "", "}}": ""}, t)
	ps := regex.find_all_string_submatch_n(`\{([^{}]*)\}`, inner, -1)
	rest := regex.replace(inner, `\{[^{}]*\}`, "")
	not regex.match(`[{}]`, rest)
} else := "?"

# The raw text with the comment removed, strings intact.
_flow_py_nocom(l) := concat("", [t | some t in _flow_py_tokens(l); not startswith(t, "#")])

_flow_py_rawind(l) := count(l) - count(trim_left(l, " \t"))

_flow_py_ind(raw, code) := -1 if trim_space(code) == ""
else := _flow_py_rawind(raw)

_flow_py_def_re := `^\s*(?:async\s+)?def\s`

# The first line of the body of the def enclosing line i (at most 120 up).
_flow_py_start(lines, i) := d + 1 if {
	me := _flow_py_rawind(lines[i])
	ds := [k |
		some k in numbers.range(max([0, i - 120]), i - 1)
		k < i
		contains(lines[k], "def")
		regex.match(_flow_py_def_re, lines[k])
		_flow_py_rawind(lines[k]) < me
	]
	count(ds) > 0
	d := max(ds)
} else := max([0, i - 120])

# The nearest code line above with a smaller indent: the block header.
_flow_py_par(ind, n) := max(hs) if {
	ind[n] >= 0
	hs := [h | some h in numbers.range(0, n - 1); h < n; h >= 0; ind[h] >= 0; ind[h] < ind[n]]
	count(hs) > 0
} else := -1

_flow_py_up(par, h) := par[h] if h >= 0
else := -1

_flow_py_anc(ctx, n) := {h | some h in [p1, p2, p3, p4, p5, p6, p7, p8]; h >= 0} if {
	p1 := _flow_py_up(ctx.par, n)
	p2 := _flow_py_up(ctx.par, p1)
	p3 := _flow_py_up(ctx.par, p2)
	p4 := _flow_py_up(ctx.par, p3)
	p5 := _flow_py_up(ctx.par, p4)
	p6 := _flow_py_up(ctx.par, p5)
	p7 := _flow_py_up(ctx.par, p6)
	p8 := _flow_py_up(ctx.par, p7)
}

_flow_py_asg_re := `^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?(\+?=)(?:[^=]|$)`

_flow_py_ctx(lines, i) := ctx if {
	i > 0
	s := _flow_py_start(lines, i)
	raw := array.slice(lines, s, i + 1)
	cb := [_flow_py_code(l) | some l in raw]
	ind := [_flow_py_ind(raw[n], cb[n]) | some n in numbers.range(0, count(raw) - 1)]
	par := [_flow_py_par(ind, n) | some n in numbers.range(0, count(raw) - 1)]
	t := i - s
	defs := [d |
		some n in numbers.range(0, t - 1)
		n < t
		b := cb[n]
		contains(b, "=")
		m := regex.find_all_string_submatch_n(_flow_py_asg_re, b, 1)
		count(m) > 0
		not m[0][1] in _flow_py_kw
		d := {"v": m[0][1], "n": n, "op": m[0][2]}
	]
	base := {"s": s, "t": t, "raw": raw, "cb": cb, "ind": ind, "par": par, "defs": defs}
	names := {d.v | some d in defs}
	mut := {v | some v in names; _flow_py_mut1(base, v)} | _flow_py_later(base, lines, i)
	b2 := object.union(base, {"mut": mut})
	single := {v: r |
		some v in names
		not v in mut
		ds := [d | some d in defs; d.v == v]
		count(ds) == 1
		ds[0].op == "="
		r := trim_space(_flow_py_rhs(b2, ds[0].n, v))
	}
	b3 := object.union(b2, {"single": single})
	ctx := object.union(b3, {
		"ints": {v: to_number(r) | some v, r in single; regex.match(`^-?\d{1,9}$`, r)},
		"strs": {v: substring(r, 1, count(r) - 2) | some v, r in single; regex.match(`^(?:'[^'\\]*'|"[^"\\]*")$`, r)},
	})
}

# v is (re)bound other than by the plain assignments ctx.defs recognised.
_flow_py_mut1(ctx, v) if {
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.cb[n]
	contains(b, v)
	regex.match(_flow_py_mut_re(v), b)
}

_flow_py_mut1(ctx, v) if {
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.cb[n]
	contains(b, v)
	contains(b, "=")
	k := count(regex.find_n(concat("", [`(?:^\s*|[=;:]\s*)`, v, `\s*(?::[^=]+)?=(?:[^=]|$)`]), b, -1))
	k > count([1 | some d in ctx.defs; d.n == n; d.v == v; d.op == "="])
}

_flow_py_mut1(ctx, v) if {
	some n in numbers.range(0, ctx.t - 1)
	n < ctx.t
	b := ctx.cb[n]
	contains(b, v)
	contains(b, ",")
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_*(\[][\w\s,*()\[\].]*?)\s*=(?:[^=]|$)`, b, 1)
	count(m) > 0
	contains(m[0][1], ",")
	regex.match(concat("", [`\b`, v, `\b`]), m[0][1])
}

_flow_py_mut_re(v) := concat("", [
	`(?:^|[^\w.])`, v, `\s*(?:[-*/%&|^@]|//|\*\*|<<|>>)=|(?:^|[^\w.])`, v, `\s*:=`,
	`|^\s*(?:async\s+)?for\s+[^=]*?\b`, v, `\b[^=]*?\s+in\b`,
	`|\bas\s+`, v, `\b|^\s*(?:from\s+\S+\s+)?import\s.*\b`, v, `\b`,
	`|^\s*(?:global|nonlocal)\s.*\b`, v, `\b|^\s*del\s+`, v, `\s*$`,
])

# Names bound later in a loop that encloses line i: they reach i again.
_flow_py_later(ctx, lines, i) := set() if {
	not _flow_py_loop_anc(ctx)
} else := {w |
	h := _flow_py_loop_anc(ctx)
	end := min([count(lines) - 1, i + 120])
	d := ctx.ind[h]
	outs := [k | some k in numbers.range(i + 1, end); k > i; c := _flow_py_code(lines[k]); trim_space(c) != ""; _flow_py_rawind(lines[k]) <= d]
	e := min(array.concat(outs, [end + 1]))
	some k in span(i + 1, e - 1)
	k > i
	k < e
	c := _flow_py_code(lines[k])
	some w in _flow_py_targets(c)
}

_flow_py_loop_anc(ctx) := min(ls) if {
	ls := [h | some h in _flow_py_anc(ctx, ctx.t); regex.match(`^\s*(?:async\s+)?(?:for|while)\b`, ctx.cb[h])]
	count(ls) > 0
}

_flow_py_targets(c) := {w |
	some m in regex.find_all_string_submatch_n(`^\s*([^=]*?)\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>|:)?=(?:[^=]|$)|^\s*(?:async\s+)?for\s+(.*?)\s+in\b|\bas\s+(\w+)`, c, -1)
	some w in regex.find_n(`[A-Za-z_]\w*`, concat(" ", [m[1], m[2], m[3]]), -1)
}

# The right-hand side of v's assignment on window line n (raw, comment
# removed), when its brackets balance on that line.
_flow_py_rhs(ctx, n, v) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*(?::[^=]+)?\+?=\s*(.*?)\s*$`]), _flow_py_nocom(ctx.raw[n]), 1)
	count(m) > 0
	_flow_py_bal(m[0][1])
}

_flow_py_bal(r) if {
	c := _flow_py_code(r)
	count(regex.find_n(`[(\[{]`, c, -1)) == count(regex.find_n(`[)\]}]`, c, -1))
}

# ── Which definitions reach a line ───────────────────────────────────────

# "dom" runs on every path from the definition's block to line x, "dead" is
# on a branch never taken, "scope" belongs to a nested def or class, "cond"
# is anything else.
_flow_py_status(ctx, n, x) := st if {
	ax := _flow_py_anc(ctx, x)
	vs := {_flow_py_hval(ctx, h) | some h in _flow_py_anc(ctx, n); not h in ax}
	st := _flow_py_st(vs)
}

_flow_py_st(vs) := "scope" if "scope" in vs
else := "dead" if "f" in vs
else := "cond" if "?" in vs
else := "dom"

_flow_py_hval(ctx, h) := "scope" if {
	regex.match(`^\s*(?:async\s+)?(?:def|class)\b`, ctx.cb[h])
} else := "t" if {
	regex.match(`^\s*(?:(?:async\s+)?with\b.*|finally\s*|match\b.*):\s*$`, ctx.cb[h])
} else := v if {
	regex.match(`^\s*if\b.*:\s*$`, ctx.cb[h])
	v := _flow_py_hcond(ctx, h)
} else := v if {
	regex.match(`^\s*(?:elif\b.*|else\s*):\s*$`, ctx.cb[h])
	v := _flow_py_branch(ctx, h)
} else := v if {
	regex.match(`^\s*case\b.*:\s*$`, ctx.cb[h])
	v := _flow_py_case(ctx, h)
} else := "?"

_flow_py_hcond(ctx, h) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:el)?if\s+(.*?)\s*:\s*$`, _flow_py_nocom(ctx.raw[h]), 1)
	count(m) > 0
	v := _flow_py_cond(ctx, m[0][1])
} else := "?"

# An elif/else: decided by the constant conditions of the if/elif chain.
_flow_py_branch(ctx, h) := v if {
	d := ctx.ind[h]
	ifs := [g | some g in numbers.range(max([0, h - 120]), h - 1); g < h; ctx.ind[g] == d; regex.match(`^\s*if\b.*:\s*$`, ctx.cb[g])]
	count(ifs) > 0
	g0 := max(ifs)
	mids := [k | some k in span(g0 + 1, h - 1); k < h; k > g0; ctx.ind[k] >= 0; ctx.ind[k] <= d]
	every k in mids {
		ctx.ind[k] == d
		regex.match(`^\s*elif\b.*:\s*$`, ctx.cb[k])
	}
	prior := array.concat([_flow_py_hcond(ctx, g0)], [_flow_py_hcond(ctx, k) | some k in mids])
	v := _flow_py_after(ctx, h, prior)
} else := "?"

_flow_py_after(ctx, h, prior) := "f" if "t" in prior
else := v if {
	every p in prior {
		p == "f"
	}
	v := _flow_py_own(ctx, h)
} else := "f" if {
	regex.match(`^\s*elif\b`, ctx.cb[h])
	_flow_py_hcond(ctx, h) == "f"
} else := "?"

_flow_py_own(ctx, h) := "t" if regex.match(`^\s*else\s*:`, ctx.cb[h])
else := _flow_py_hcond(ctx, h)

# ── Constant conditions ──────────────────────────────────────────────────

_flow_py_cond(ctx, c) := r if {
	x := _flow_py_unparen(trim_space(c))
	r := _flow_py_cond1(ctx, x)
}

_flow_py_unparen(x) := substring(x, 1, count(x) - 2) if {
	regex.match(`^\((?:[^()]|\([^()]*\))*\)$`, x)
} else := x

_flow_py_cond1(_, "True") := "t"

_flow_py_cond1(_, "False") := "f"

# 'lit' in name / 'lit' not in name, the name holding a string literal.
_flow_py_cond1(ctx, x) := r if {
	m := regex.find_all_string_submatch_n(`^(?:'([^'\\]*)'|"([^"\\]*)")\s+(not\s+)?in\s+(.+)$`, x, 1)
	count(m) > 0
	hay := _flow_py_strval(ctx, trim_space(m[0][4]))
	has := contains(hay, concat("", [m[0][1], m[0][2]]))
	r := _flow_py_tf(has != (m[0][3] != ""))
}

_flow_py_cond1(ctx, x) := r if {
	not regex.match(`^["']|^(?:True|False)$`, x)
	toks := regex.find_n(`\d+|[A-Za-z_]\w*|//|>=|<=|==|!=|[-+*%()<>]|\S`, x, -1)
	count(toks) > 0
	every k in toks {
		_flow_py_tok_ok(ctx, k)
	}
	s := concat("", [_flow_py_ntok(ctx, k) | some k in toks])
	r := _flow_eval_cond(s)
}

_flow_py_tf(true) := "t"

_flow_py_tf(false) := "f"

_flow_py_tok_ok(_, k) if regex.match(`^(?:\d+|//|>=|<=|==|!=|[-+*%()<>])$`, k)

_flow_py_tok_ok(ctx, k) if _ = ctx.ints[k]

_flow_py_ntok(ctx, k) := format_int(ctx.ints[k], 10) if _ = ctx.ints[k]
else := "/" if k == "//"
else := k

_flow_py_strval(_, x) := substring(x, 1, count(x) - 2) if regex.match(`^(?:'[^'\\]*'|"[^"\\]*")$`, x)

_flow_py_strval(ctx, x) := ctx.strs[x]

# ── match on a constant ──────────────────────────────────────────────────

_flow_py_case(ctx, h) := v if {
	p := ctx.par[h]
	p >= 0
	m := regex.find_all_string_submatch_n(`^\s*match\s+(.*?)\s*:\s*$`, _flow_py_nocom(ctx.raw[p]), 1)
	count(m) > 0
	sel := _flow_py_sel(ctx, trim_space(m[0][1]))
	d := ctx.ind[h]
	sibs := [k | some k in numbers.range(p + 1, h); k > p; k <= h; ctx.ind[k] == d]
	labs := [_flow_py_labels(_flow_py_nocom(ctx.raw[k])) | some k in sibs]
	v := _flow_py_pick(labs, sel)
} else := "?"

_flow_py_labels(raw) := {"d": true, "s": set()} if {
	regex.match(`^\s*case\s+_\s*:\s*$`, raw)
} else := {"d": false, "s": ls} if {
	m := regex.find_all_string_submatch_n(`^\s*case\s+(.*?)\s*:\s*$`, raw, 1)
	count(m) > 0
	alts := [trim_space(a) | some a in split(m[0][1], "|")]
	every a in alts {
		regex.match(`^(?:'[^'\\|]*'|"[^"\\|]*"|-?\d+)$`, a)
	}
	ls := {_flow_py_norm(a) | some a in alts}
} else := {"u": true}

_flow_py_pick(labs, sel) := "?" if {
	some l in array.slice(labs, 0, count(labs) - 1)
	l.u
} else := "f" if {
	some l in array.slice(labs, 0, count(labs) - 1)
	_flow_py_hit(l, sel)
} else := "?" if {
	labs[count(labs) - 1].u
} else := "t" if {
	_flow_py_hit(labs[count(labs) - 1], sel)
} else := "f"

_flow_py_hit(l, _) if l.d == true

_flow_py_hit(l, sel) if sel in l.s

_flow_py_norm(x) := concat("", ["s:", substring(x, 1, count(x) - 2)]) if regex.match(`^["']`, x)

_flow_py_norm(x) := concat("", ["n:", format_int(to_number(x), 10)]) if regex.match(`^-?\d+$`, x)

# The value a match selects on: a literal, a local holding one, a character
# of a constant string, or a local assigned once from one of those.
_flow_py_sel(ctx, x) := v if v := _flow_py_sel1(ctx, x)
else := v if {
	regex.match(`^[A-Za-z_]\w*$`, x)
	v := _flow_py_sel1(ctx, ctx.single[x])
}

_flow_py_sel1(_, x) := _flow_py_norm(x) if regex.match(`^(?:'[^'\\]*'|"[^"\\]*"|-?\d+)$`, x)

_flow_py_sel1(ctx, x) := concat("", ["n:", format_int(ctx.ints[x], 10)]) if _ = ctx.ints[x]

_flow_py_sel1(ctx, x) := concat("", ["s:", ctx.strs[x]]) if _ = ctx.strs[x]

_flow_py_sel1(ctx, x) := concat("", ["s:", substring(sv, k, 1)]) if {
	m := regex.find_all_string_submatch_n(`^('[^'\\]*'|"[^"\\]*"|[A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]$`, x, 1)
	count(m) > 0
	sv := _flow_py_strval(ctx, m[0][1])
	k := to_number(m[0][2])
	k < count(sv)
}

# ── Right-hand sides and what they need to be constant ───────────────────

_flow_py_reqs_of(ctx, lines, r, n, M) := q if {
	tm := regex.find_all_string_submatch_n(`^(.*?)\s+if\s+(.*?)\s+else\s+(.*)$`, r, 1)
	count(tm) > 0
	regex.match(`\sif\s.*\selse\s`, _flow_py_code(r))
	q := _flow_tern(_flow_py_tcond(ctx, tm[0][2]), tm[0][1], tm[0][3], ctx.s + n)
} else := _flow_py_expr_reqs(ctx, lines, r, n, M)

_flow_py_tcond(ctx, c) := v if v := _flow_py_cond(ctx, c)
else := "?"

_flow_py_read_re := `\b([A-Za-z_]\w*)\s*(?:\[\s*([^\[\]]*?)\s*\]|\.\s*get\s*\(\s*([^()]*?)\s*\))`

_flow_py_expr_reqs(ctx, lines, r, n, M) := array.concat(array.concat([[i3.t, ctx.s + n]], [x[1] | some x in res]), array.concat(i1.q, array.concat(i2.q, i3.q))) if {
	reads := regex.find_all_string_submatch_n(_flow_py_read_re, r, -1)
	res := [[g[0], e] | some g in reads; not regex.match(`\.\s*$`, substring(r, 0, indexof(r, g[0]))); e := _flow_py_cget(ctx, g[1], g[2], g[3], n)]
	r1 := strings.replace_n({x[0]: `""` | some x in res}, r)
	r2 := _flow_py_drop_calls(r1, M)
	i1 := _flow_py_inert_round(ctx, lines, r2, n)
	i2 := _flow_py_inert_round(ctx, lines, i1.t, n)
	i3 := _flow_py_inert_round(ctx, lines, i2.t, n)
}

# ── Inert calls (Python) ─────────────────────────────────────────────────
# The same reading as the inert calls above: a call that is not named like a
# source, whose arguments are all constants, on a class, an imported module,
# or a local that is itself a constant-argument construction or inert call
# and is only ever called with constant arguments, has a constant value.

_flow_py_inert_re := `(^|[^\w.])((?:[A-Za-z_]\w*\s*\.\s*)*)([A-Za-z_]\w*)\s*\(((?:[rRbBuUfF]{0,2}"(?:[^"\\]|\\.)*"|[rRbBuUfF]{0,2}'(?:[^'\\]|\\.)*'|[^()"'])*)\)`

_flow_py_srcname_re := `(?i)^(?:(?:read|recv|receive|input|next|query|execute|exec|fetch|load|open|poll|pop|accept|lines|scan|connect|lookup|resolve|run|call|invoke|spawn|start|eval|getenv|getpass|popen|system|check|communicate)\w*|get\w*(?:param|header|cookie|query|input|reader|stream|body|attr|session|request|remote|env|prop|uri|url|path|data|value|line|content|text|message|result|resource|socket|arg|host|addr|json|form|file)\w*)$`

_flow_py_srcroot := {"os", "sys", "subprocess", "socket", "requests", "urllib", "http", "flask", "request", "shutil", "glob", "pathlib", "pickle", "yaml", "sqlite3", "cursor", "conn", "connection", "db", "session", "environ", "stdin", "argv", "headers", "cookies", "form", "files", "args", "input", "builtins", "ctypes", "importlib", "marshal", "shelve"}

_flow_py_srctype_re := `(?:Reader|Stream|Scanner|Socket|Channel|Connection|Client|Request|Session|Process|Popen|Cursor|Console|Path|File)$`

_flow_py_imported(lines, root) if {
	some l in lines
	contains(l, root)
	regex.match(concat("", [`^\s*(?:import\s+[\w., ]*\b`, root, `\b|from\s+[\w.]+\s+import\s+[\w., ()]*\b`, root, `\b)`]), l)
}

_flow_py_inert_kind(_, m) := ["new", ""] if {
	trim_space(m[2]) == ""
	regex.match(`^[A-Z]\w*[a-z]\w*$`, m[3])
	not regex.match(_flow_py_srctype_re, m[3])
}

_flow_py_inert_kind(lines, m) := [kind, root] if {
	ch := regex.replace(m[2], `\s+`, "")
	ch != ""
	segs := split(trim_suffix(ch, "."), ".")
	root := segs[0]
	not root in _flow_py_srcroot
	not root in _flow_py_kw
	every s in segs {
		not s in _flow_py_srcroot
	}
	not regex.match(_flow_py_srcname_re, m[3])
	kind := _flow_py_recv_kind(lines, root, count(segs))
}

_flow_py_recv_kind(_, root, _) := "type" if regex.match(`^[A-Z]`, root)

_flow_py_recv_kind(lines, root, _) := "type" if {
	regex.match(`^[a-z_]`, root)
	_flow_py_imported(lines, root)
}

_flow_py_recv_kind(lines, root, 1) := "local" if {
	regex.match(`^[a-z_]`, root)
	not _flow_py_imported(lines, root)
}

_flow_py_inert_hits(lines, r) := [h |
	contains(r, "(")
	some m in regex.find_all_string_submatch_n(_flow_py_inert_re, r, -1)
	not m[3] in _flow_py_kw
	k := _flow_py_inert_kind(lines, m)
	h := {"all": substring(m[0], count(m[1]), -1), "kind": k[0], "recv": k[1], "args": m[4]}
]

_flow_py_inert_round(ctx, lines, r, n) := {"t": strings.replace_n({h.all: `""` | some h in hs}, r), "q": [q |
	some h in hs
	some q in _flow_py_inert_reqs(ctx, lines, h, n)
]} if {
	hs := _flow_py_inert_hits(lines, r)
	count(hs) > 0
} else := {"t": r, "q": []}

_flow_py_inert_reqs(ctx, lines, h, n) := array.concat(_flow_py_args_req(h, ctx.s + n), _flow_py_recv_reqs(ctx, lines, h, n))

# Each positional or keyword argument is its own requirement: a constant list
# of them is constant even though a comma is not an expression.
_flow_py_pieces(a, j) := [[regex.replace(trim_space(m[0]), `^[A-Za-z_]\w*\s*=\s*`, ""), j] |
	some m in regex.find_all_string_submatch_n(`(?:[rRbBuUfF]{0,2}"(?:[^"\\]|\\.)*"|[rRbBuUfF]{0,2}'(?:[^'\\]|\\.)*'|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|[^,"'()])+`, a, -1)
	trim_space(m[0]) != ""
]

_flow_py_args_req(h, j) := _flow_py_pieces(h.args, j)

_flow_py_recv_reqs(ctx, lines, h, n) := array.concat([[h.recv, ctx.s + n]], _flow_py_call_mentions(ctx, lines, h.recv)) if h.kind == "local"

_flow_py_recv_reqs(_, _, h, _) := [] if h.kind != "local"

# Every call on local v above the asked line must have constant arguments.
_flow_py_mention_args(ctx, v) := [[a[1], ctx.s + k] |
	some k in numbers.range(0, ctx.t - 1)
	k < ctx.t
	contains(ctx.cb[k], v)
	st := _flow_py_stmt_from(ctx, v, k)
	some a in regex.find_all_string_submatch_n(`\.\s*[A-Za-z_]\w*\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, st, -1)
	trim_space(a[1]) != ""
]

_flow_py_call_mentions(ctx, lines, v) := [q |
	some x in _flow_py_mention_args(ctx, v)
	some q in _flow_py_static_reqs(lines, x[0], x[1])
]

_flow_py_static_reqs(lines, a, j) := array.concat(_flow_py_pieces(s3.t, j), array.concat(s1.q, array.concat(s2.q, s3.q))) if {
	s1 := _flow_py_static_round(lines, a, j)
	s2 := _flow_py_static_round(lines, s1.t, j)
	s3 := _flow_py_static_round(lines, s2.t, j)
}

_flow_py_static_round(lines, r, j) := {"t": strings.replace_n({h.all: `""` | some h in hs}, r), "q": [q | some h in hs; some q in _flow_py_pieces(h.args, j)]} if {
	hs := [h | some h in _flow_py_inert_hits(lines, r); h.kind != "local"]
	count(hs) > 0
} else := {"t": r, "q": []}

_flow_py_stmt_from(ctx, v, k) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])(`, v, `\s*\..*)$`]), ctx.cb[k], 1)
	count(m) > 0
}

_flow_py_def_mentions(ctx, lines, v, r) := _flow_py_call_mentions(ctx, lines, v) if count(_flow_py_inert_hits(lines, r)) > 0

_flow_py_def_mentions(ctx, lines, v, r) := [] if count(_flow_py_inert_hits(lines, r)) == 0

_flow_py_drop_calls(r, M) := r if count(M.m) == 0

_flow_py_drop_calls(r, M) := strings.replace_n({x[0]: `""` |
	some x in regex.find_all_string_submatch_n(`(?:\bself\s*\.\s*)?\b([A-Za-z_]\w*)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`, r, -1)
	x[1] in M.m
	not regex.match(`\.\s*$`, substring(r, 0, indexof(r, x[0])))
}, r) if count(M.m) > 0

# A text that is a constant: literals, numbers, UPPER_CASE names, names C
# holds as constant (last defined above `line`), a constant string indexed.
_flow_py_sconst(text, line, C) if {
	b0 := _flow_py_code(text)
	b1 := regex.replace(b0, `\.\s*(?:strip|lstrip|rstrip|upper|lower|title|capitalize|casefold|swapcase)\s*\(\s*\)`, "")
	b := regex.replace(b1, `\b([A-Za-z_]\w*)\s*\[\s*-?\d+\s*\]`, "$1")
	trim_space(b) != ""
	not regex.match(`[\[\]{}:;,?!@=~\\]|\b(?:lambda|if|for|await|yield)\b`, b)
	not regex.match(`[A-Za-z_]\w*\s*\(|\.\s*[A-Za-z_]`, b)
	count(regex.find_n(`\(`, b, -1)) == count(regex.find_n(`\)`, b, -1))
	every w in regex.find_n(`[A-Za-z_]\w*`, b, -1) {
		_flow_py_cname(w, line, C)
	}
}

_flow_py_cname(w, _, _) if w in {"True", "False", "None", "and", "or", "not", "in", "is"}

_flow_py_cname(w, _, _) if regex.match(`^[A-Z][A-Z0-9_]*$`, w)

_flow_py_cname(w, line, C) if C[w] < line

# ── Lists, dicts and ConfigParsers used as value carriers ────────────────

_flow_py_sk := `'[^'\\]*'|"[^"\\]*"`

# The [value text, line] stored under the index/key a read names, when L is
# created once in the method and every use of it before the read is
# understood.
_flow_py_cget(ctx, L, sub, gargs, j) := e if {
	ds := [d | some d in ctx.defs; d.v == L]
	count(ds) == 1
	not L in ctx.mut
	d := ds[0]
	d.n < j
	d.op == "="
	_flow_py_status(ctx, d.n, j) == "dom"
	r := trim_space(_flow_py_rhs(ctx, d.n, L))
	kind := _flow_py_ckind(r)
	init := _flow_py_cinit(kind, r, ctx.s + d.n)
	re := concat("", [`\b`, L, `\b`])
	refs := [k | some k in span(d.n + 1, j - 1); k < j; k > d.n; regex.match(re, ctx.cb[k])]
	every k in refs {
		_flow_py_use_ok(ctx.cb[k], L)
	}
	muts := [k | some k in refs; regex.match(_flow_py_mutc_re(L), ctx.cb[k])]
	sts := {k: s | some k in muts; s := _flow_py_status(ctx, k, j)}
	every k in muts {
		sts[k] in {"dom", "dead"}
	}
	ops := [o | some k in muts; sts[k] == "dom"; o := _flow_py_cop(kind, L, _flow_py_nocom(ctx.raw[k]), ctx.s + k)]
	count(ops) == count([k | some k in muts; sts[k] == "dom"])
	e := _flow_py_cread(kind, array.concat(init, ops), sub, gargs)
}

_flow_py_ckind(r) := "list" if regex.match(`^(?:\[.*\]|list\(\s*\))$`, r)

_flow_py_ckind(r) := "map" if regex.match(`^(?:\{.*\}|dict\(\s*\))$`, r)

_flow_py_ckind(r) := "cfg" if regex.match(`^(?:configparser\s*\.\s*)?(?:Raw|Safe)?ConfigParser\(\s*\)$`, r)

_flow_py_cinit(_, r, _) := [] if regex.match(`^(?:\[\s*\]|\{\s*\}|\w+\(\s*\)|configparser\s*\.\s*\w+\(\s*\))$`, r)

_flow_py_cinit("list", r, k) := [{"t": "add", "x": trim_space(x), "k": k} | some x in split(substring(r, 1, count(r) - 2), ",")] if {
	inner := substring(r, 1, count(r) - 2)
	trim_space(inner) != ""
	every x in split(inner, ",") {
		regex.match(`^\s*(?:'[^'\\,]*'|"[^"\\,]*"|-?\d+|[A-Za-z_]\w*)\s*$`, x)
	}
}

_flow_py_cinit("map", r, k) := [{"t": "put", "key": _flow_py_norm(trim_space(p[0])), "x": trim_space(p[1]), "k": k} |
	some x in split(substring(r, 1, count(r) - 2), ",")
	p := split(x, ":")
] if {
	inner := substring(r, 1, count(r) - 2)
	trim_space(inner) != ""
	every x in split(inner, ",") {
		regex.match(`^\s*(?:'[^'\\,:]*'|"[^"\\,:]*")\s*:\s*(?:'[^'\\,:]*'|"[^"\\,:]*"|-?\d+|[A-Za-z_]\w*)\s*$`, x)
	}
}

_flow_py_mutc_re(L) := concat("", [`\b`, L, `\s*\.\s*(?:append|insert|pop|clear|set|add_section|remove_option|remove_section|update|setdefault|extend|remove|sort|reverse|popitem)\s*\(|\b`, L, `\s*\[[^\]]*\]\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)?=(?:[^=]|$)|\bdel\s+`, L, `\b`])

# Every mention of L on the line is a call or subscript this analysis
# understands, and a mutating one is the whole statement.
_flow_py_use_ok(b, L) if {
	all := count(regex.find_n(concat("", [`\b`, L, `\b`]), b, -1))
	ok := count(regex.find_n(concat("", [`\b`, L, `\s*(?:\.\s*(?:append|insert|pop|clear|get|keys|values|items|add_section|has_section|has_option|set)\s*\(|\[)|\blen\s*\(\s*`, L, `\s*\)`]), b, -1))
	all == ok
	muts := count(regex.find_n(_flow_py_mutc_re(L), b, -1))
	_flow_py_mut_stmt(b, L, muts)
}

_flow_py_mut_stmt(_, _, 0)

_flow_py_mut_stmt(b, L, 1) if regex.match(concat("", [`^\s*(?:del\s+)?`, L, `\s*[.\[]`]), b)

_flow_py_cop(kind, L, raw, k) := o if {
	o := _flow_py_cop1(kind, L, trim_space(raw), k)
}

_flow_py_cop1("list", L, s, k) := {"t": "add", "x": m[0][1], "k": k} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\.\s*append\s*\((.*)\)$`]), s, 1)
	count(m) > 0
	not regex.match(`^(?:[^(),]|\((?:[^()]|\([^()]*\))*\))*,`, _flow_py_code(m[0][1]))
}

_flow_py_cop1("list", L, s, k) := {"t": "ins", "i": to_number(m[0][1]), "x": m[0][2], "k": k} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\.\s*insert\s*\(\s*(\d+)\s*,\s*(.*)\)$`]), s, 1)
	count(m) > 0
}

_flow_py_cop1("list", L, s, _) := {"t": "rm", "i": to_number(m[0][1])} if {
	m := regex.find_all_string_submatch_n(concat("", [`^(?:`, L, `\s*\.\s*pop\s*\(\s*(\d+)\s*\)|del\s+`, L, `\s*\[\s*(\d+)\s*\])$`]), s, 1)
	count(m) > 0
	m[0][1] != ""
}

_flow_py_cop1("list", L, s, _) := {"t": "rm", "i": to_number(m[0][2])} if {
	m := regex.find_all_string_submatch_n(concat("", [`^(?:`, L, `\s*\.\s*pop\s*\(\s*(\d+)\s*\)|del\s+`, L, `\s*\[\s*(\d+)\s*\])$`]), s, 1)
	count(m) > 0
	m[0][2] != ""
}

_flow_py_cop1("list", L, s, _) := {"t": "rmlast"} if regex.match(concat("", [`^`, L, `\s*\.\s*pop\s*\(\s*\)$`]), s)

_flow_py_cop1("list", L, s, k) := {"t": "set", "i": to_number(m[0][1]), "x": m[0][2], "k": k} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\[\s*(\d+)\s*\]\s*=\s*(.*)$`]), s, 1)
	count(m) > 0
}

_flow_py_cop1(_, L, s, _) := {"t": "clear"} if regex.match(concat("", [`^`, L, `\s*\.\s*clear\s*\(\s*\)$`]), s)

_flow_py_cop1("map", L, s, k) := {"t": "put", "key": _flow_py_norm(m[0][1]), "x": m[0][2], "k": k} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\[\s*(`, _flow_py_sk, `)\s*\]\s*=\s*(.*)$`]), s, 1)
	count(m) > 0
}

_flow_py_cop1("map", L, s, _) := {"t": "del", "key": _flow_py_norm(m[0][1])} if {
	m := regex.find_all_string_submatch_n(concat("", [`^(?:`, L, `\s*\.\s*pop\s*\(\s*(`, _flow_py_sk, `)\s*\)|del\s+`, L, `\s*\[\s*(`, _flow_py_sk, `)\s*\])$`]), s, 1)
	count(m) > 0
	m[0][1] != ""
}

_flow_py_cop1("map", L, s, _) := {"t": "del", "key": _flow_py_norm(m[0][2])} if {
	m := regex.find_all_string_submatch_n(concat("", [`^(?:`, L, `\s*\.\s*pop\s*\(\s*(`, _flow_py_sk, `)\s*\)|del\s+`, L, `\s*\[\s*(`, _flow_py_sk, `)\s*\])$`]), s, 1)
	count(m) > 0
	m[0][2] != ""
}

_flow_py_cop1("cfg", L, s, _) := {"t": "noop"} if regex.match(concat("", [`^`, L, `\s*\.\s*add_section\s*\([^()]*\)$`]), s)

_flow_py_cop1("cfg", L, s, k) := {"t": "put", "key": concat("|", [_flow_py_norm(m[0][1]), _flow_py_norm(m[0][2])]), "x": m[0][3], "k": k} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\.\s*set\s*\(\s*(`, _flow_py_sk, `)\s*,\s*(`, _flow_py_sk, `)\s*,\s*(.*)\)$`]), s, 1)
	count(m) > 0
}

_flow_py_cop1("cfg", L, s, _) := {"t": "del", "key": concat("|", [_flow_py_norm(m[0][1]), _flow_py_norm(m[0][2])])} if {
	m := regex.find_all_string_submatch_n(concat("", [`^`, L, `\s*\.\s*remove_option\s*\(\s*(`, _flow_py_sk, `)\s*,\s*(`, _flow_py_sk, `)\s*\)$`]), s, 1)
	count(m) > 0
}

# The read: list[i], dict['k'] / dict.get('k'), parser.get('section', 'k').
_flow_py_cread("list", ops, sub, gargs) := [el[0], el[1]] if {
	gargs == ""
	regex.match(`^-?\d+$`, sub)
	count(ops) <= 10
	s := _flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep(_flow_py_lstep([], ops, 0), ops, 1), ops, 2), ops, 3), ops, 4), ops, 5), ops, 6), ops, 7), ops, 8), ops, 9)
	k := _flow_py_idx(to_number(sub), count(s))
	el := s[k]
}

_flow_py_cread("map", ops, sub, gargs) := _flow_cval("map", ops, _flow_py_norm(sub)) if {
	gargs == ""
	regex.match(concat("", [`^(?:`, _flow_py_sk, `)$`]), sub)
}

_flow_py_cread("map", ops, sub, gargs) := _flow_cval("map", ops, _flow_py_norm(gargs)) if {
	sub == ""
	regex.match(concat("", [`^(?:`, _flow_py_sk, `)$`]), gargs)
}

_flow_py_cread("cfg", ops, sub, gargs) := _flow_cval("map", ops, concat("|", [_flow_py_norm(m[0][1]), _flow_py_norm(m[0][2])])) if {
	sub == ""
	m := regex.find_all_string_submatch_n(concat("", [`^(`, _flow_py_sk, `)\s*,\s*(`, _flow_py_sk, `)$`]), gargs, 1)
	count(m) > 0
}

_flow_py_idx(k, _) := k if k >= 0

_flow_py_idx(k, n) := n + k if k < 0

_flow_py_lstep(s, ops, k) := s if k >= count(ops)

_flow_py_lstep(s, ops, k) := _flow_py_lop(s, ops[k]) if k < count(ops)

_flow_py_lop(s, o) := _flow_lop(s, {"t": "rm", "i": count(s) - 1}) if {
	o.t == "rmlast"
	count(s) > 0
}

_flow_py_lop(s, o) := _flow_lop(s, o) if o.t != "rmlast"

# ── Same-file functions whose every return is constant ───────────────────

_flow_py_called(ctx) := {m[1] |
	some b in ctx.cb
	contains(b, "(")
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.]|\bself\s*\.\s*)([A-Za-z_]\w*)\s*\(`, b, -1)
	not m[1] in _flow_py_kw
}

_flow_py_const_fns(lines, names) := {nm |
	some nm in names
	re := concat("", [`^\s*(?:async\s+)?def\s+`, nm, `\s*\(`])
	decls := [k | some k, l in lines; contains(l, nm); contains(l, "def"); regex.match(re, l)]
	count(decls) > 0
	every k in decls {
		_flow_py_fn_const(lines, k)
	}
}

_flow_py_fn_const(lines, k) if {
	d := _flow_py_rawind(lines[k])
	end := min([count(lines) - 1, k + 150])
	outs := [x | some x in numbers.range(k + 1, end); x > k; trim_space(_flow_py_code(lines[x])) != ""; _flow_py_rawind(lines[x]) <= d]
	e := min(array.concat(outs, [end + 1]))
	body := [lines[x] | some x in span(k + 1, e - 1); x > k; x < e]
	count(body) > 0
	count(regex.find_n(`"""|'''`, concat("\n", body), -1)) % 2 == 0
	not regex.match(`(?m)^\s*(?:.*[^\w.])?yield\b`, concat("\n", body))
	rets := [x | some x in span(k + 1, e - 1); x > k; x < e; regex.match(`^\s*return\b`, lines[x])]
	count(rets) > 0
	every x in rets {
		_flow_py_ret_const(lines, x)
	}
}

_flow_py_ret_const(lines, x) if {
	m := regex.find_all_string_submatch_n(`^\s*return\b\s*(.*?)\s*$`, _flow_py_nocom(lines[x]), 1)
	count(m) > 0
	m[0][1] == ""
}

_flow_py_ret_const(lines, x) if {
	m := regex.find_all_string_submatch_n(`^\s*return\b\s*(.*?)\s*$`, _flow_py_nocom(lines[x]), 1)
	count(m) > 0
	m[0][1] != ""
	ctx := _flow_py_ctx(lines, x)
	M := {"m": set()}
	C := _flow_py_core(ctx, lines, M)
	every q in _flow_py_reqs_of(ctx, lines, m[0][1], ctx.t, M) {
		_flow_py_sconst(q[0], q[1], C)
	}
}

# ── Constants at a line ──────────────────────────────────────────────────

_flow_py_core(ctx, lines, M) := c4 if {
	vr := _flow_py_var_reqs(ctx, lines, M)
	c1 := _flow_py_round(vr, {})
	c2 := _flow_py_round(vr, c1)
	c3 := _flow_py_round(vr, c2)
	c4 := _flow_py_round(vr, c3)
}

_flow_py_round(vr, C) := {v: e.ln |
	some v, e in vr
	every q in e.rq {
		_flow_py_sconst(q[0], q[1], C)
	}
}

_flow_py_var_reqs(ctx, lines, M) := {v: e |
	some v in {d.v | some d in ctx.defs}
	not v in ctx.mut
	st := [[d, s] | some d in ctx.defs; d.v == v; s := _flow_py_status(ctx, d.n, ctx.t)]
	live := [x | some x in st; not x[1] in {"dead", "scope"}]
	doms := [x[0].n | some x in live; x[1] == "dom"; x[0].op == "="]
	count(doms) > 0
	b := max(doms)
	after := [x[0] | some x in live; x[0].n >= b]
	rq := [q |
		some d in after
		some q in _flow_py_def_reqs(ctx, lines, d, M)
	]
	e := {"ln": ctx.s + max([d.n | some d in after]), "rq": rq}
}

# `copy = name`: what name holds at that line (strings and numbers are
# values, so a later change to name does not reach the copy), read from the
# definitions of name above it, two copies deep. Not used inside a loop.
_flow_py_def_reqs(ctx, lines, d, M) := q if {
	w := _flow_py_bare(ctx, d)
	ds := _flow_py_at_defs(ctx, w, d.n)
	q := [x | some d2 in ds; some x in _flow_py_rhs_reqs2(ctx, lines, d2, M)]
} else := _flow_py_rhs_reqs(ctx, lines, d, M)

_flow_py_rhs_reqs2(ctx, lines, d, M) := q if {
	w := _flow_py_bare(ctx, d)
	ds := _flow_py_at_defs(ctx, w, d.n)
	q := [x | some d2 in ds; some x in _flow_py_rhs_reqs(ctx, lines, d2, M)]
} else := _flow_py_rhs_reqs(ctx, lines, d, M)

_flow_py_bare(ctx, d) := w if {
	d.op == "="
	w := trim_space(_flow_py_rhs(ctx, d.n, d.v))
	regex.match(`^[A-Za-z_]\w*$`, w)
	not w in _flow_py_kw
	w != d.v
}

# The definitions of w that can reach window line n: the last one on every
# path and those after it.
_flow_py_at_defs(ctx, w, n) := [x[0] | some x in live; x[0].n >= b] if {
	not w in ctx.mut
	not _flow_py_in_loop(ctx, n)
	st := [[d, s] | some d in ctx.defs; d.v == w; d.n < n; s := _flow_py_status(ctx, d.n, n)]
	live := [x | some x in st; not x[1] in {"dead", "scope"}]
	doms := [x[0].n | some x in live; x[1] == "dom"; x[0].op == "="]
	count(doms) > 0
	b := max(doms)
}

_flow_py_rhs_reqs(ctx, lines, d, M) := array.concat(q, _flow_py_def_mentions(ctx, lines, d.v, r)) if {
	r := _flow_py_rhs(ctx, d.n, d.v)
	q := _flow_py_reqs_of(ctx, lines, r, d.n, M)
} else := [["?", ctx.s + d.n]]

_flow_py_in_loop(ctx, n) if {
	some h in _flow_py_anc(ctx, n)
	regex.match(`^\s*(?:async\s+)?(?:for|while)\b`, ctx.cb[h])
}

flow_py_consts(lines, i) := C if {
	ctx := _flow_py_ctx(lines, i)
	M := {"m": _flow_py_const_fns(lines, _flow_py_called(ctx))}
	C := _flow_py_core(ctx, lines, M)
} else := {}

flow_py_fold(text, line, C) := text if count([v | some v, l in C; l < line]) == 0

flow_py_fold(text, line, C) := concat("", [_flow_py_fold_tok(toks, k, ns, re) | some k, _ in toks]) if {
	ns := {v | some v, l in C; l < line}
	count(ns) > 0
	re := concat("", [`(^|[^\w.])(?:`, concat("|", ns), `)\b`])
	toks := _flow_py_tokens(text)
}

# A name token is folded unless it is an attribute (`x.name`).
_flow_py_fold_tok(toks, k, ns, re) := `""` if {
	toks[k] in ns
	not _flow_py_after_dot(toks, k)
} else := concat("", [_flow_py_fold_piece(p, re) | some p in regex.find_n(`\{\{|\}\}|\{[^{}]*\}|[^{}]+|[{}]`, toks[k], -1)]) if {
	regex.match(_flow_py_str_re, toks[k])
	_flow_py_is_f(toks[k])
} else := toks[k]

_flow_py_after_dot(toks, k) if {
	k > 0
	regex.match(`\.\s*$`, toks[k - 1])
}

_flow_py_fold_piece(p, re) := regex.replace(p, re, "${1}0") if {
	startswith(p, "{")
	not startswith(p, "{{")
} else := p
