# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1047

import rego.v1

metadata := {
	"id": "VNX-1047",
	"name": "Modules with Circular Dependencies",
	"description": "Python or JavaScript/TypeScript modules of the same project that import each other in a cycle. Python imports (absolute, relative, 'from pkg import submodule') and JavaScript require(), import, export-from and import() with a relative specifier are resolved to files of the scanned tree. Reported: two modules that import each other at load time (once, on the import in the file whose path sorts first); three modules in a load-time cycle (once, on the import of the module whose path sorts first); and an import deferred into a function that closes a cycle of any length with load-time imports (on the deferred import, the usual workaround). A partially initialised module is how a validator, logger or auth handler ends up undefined when first used. Not reported: imports under 'if TYPE_CHECKING:', 'import type' and all-type import lists, cycles in which every import is deferred, package and standard-library imports, path aliases, and load-time cycles longer than three modules. Go is not covered: the Go compiler rejects import cycles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1047/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1047],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["circular-dependency", "import", "initialization", "code-quality", "cwe-1047"],
}

# ── shared path helpers ───────────────────────────────────────────────────

_vendored(path) if regex.match(`(^|/)(node_modules|bower_components|vendor|site-packages|\.venv|venv|dist|build)/`, path)

_vendored(path) if endswith(path, ".min.js")

_dir_parts(path) := array.slice(parts, 0, count(parts) - 1) if parts := split(path, "/")

# "" for the scan root, otherwise "a/b/" (the first k directories of a path)
_root(_, 0) := ""

_root(dparts, k) := concat("", [concat("/", array.slice(dparts, 0, k)), "/"]) if k > 0

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── Python ────────────────────────────────────────────────────────────────

# A module that uses relative imports is part of a package, so its own
# directory is not on sys.path and `import json` there is the standard library.
_py_rel(content) := regex.match(`(?m)^[ \t]*from[ \t]+\.`, content)

_py_import_kw(t) if startswith(t, "import ")

_py_import_kw(t) if startswith(t, "from ")

# module: runs when the module is loaded (column 0, or directly under a
# top-level try/if/with). deferred: directly inside a function body. Anything
# else (TYPE_CHECKING, a class body, a nested block) yields no edge.
_py_kind(_, _, line) := "module" if _indent(line) == 0

_py_kind(lines, i, line) := k if {
	_indent(line) > 0
	p := _py_parent(lines, i, _indent(line))
	k := _py_parent_kind(p)
}

_py_parent(lines, i, n) := lines[j] if {
	cands := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		l := lines[k]
		t := trim_left(l, " \t")
		t != ""
		not startswith(t, "#")
		_indent(l) < n
	]
	count(cands) > 0
	j := cands[count(cands) - 1]
}

_py_parent_kind(p) := "deferred" if {
	regex.match(`^\s*(async\s+)?def\s`, p)
	not contains(p, "TYPE_CHECKING")
}

_py_parent_kind(p) := "module" if {
	_indent(p) == 0
	regex.match(`^(try|except|else|finally|if|elif|with)\b`, p)
	not contains(p, "TYPE_CHECKING")
}

# The statement text, with a parenthesised name list joined onto one line.
_py_stmt(_, _, t) := t if not _open_paren(t)

_py_stmt(lines, i, t) := s if {
	_open_paren(t)
	end := min([count(lines) - 1, i + 15])
	closes := [k | some k in numbers.range(i + 1, end); contains(lines[k], ")")]
	count(closes) > 0
	s := concat(" ", [trim_space(lines[k]) | some k in numbers.range(i, closes[0])])
}

_open_paren(t) if {
	contains(t, "(")
	not contains(t, ")")
}

_py_imports contains imp if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "import ")
	not _vendored(path)
	rel := _py_rel(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "import")
	t := trim_left(line, " \t")
	_py_import_kw(t)
	kind := _py_kind(lines, i, line)
	imp := {"path": path, "i": i, "line": line, "text": _py_stmt(lines, i, t), "kind": kind, "rel": rel}
}

# absolute module name -> files, tried from every directory above the importer
# that is a sys.path entry (no __init__.py), plus the importer's own directory
# for a script-style module.
_py_abs(path, rel, mod) := {c |
	dparts := _dir_parts(path)
	mpath := replace(mod, ".", "/")
	some k in numbers.range(0, count(dparts))
	root := _root(dparts, k)
	_py_root_ok(dparts, k, root, rel)
	some suffix in [".py", "/__init__.py"]
	c := concat("", [root, mpath, suffix])
	input.file_set[c]
}

_py_root_ok(_, _, root, _) if not input.file_set[concat("", [root, "__init__.py"])]

_py_root_ok(dparts, k, _, false) if k == count(dparts)

# `from ..x.y import z` -> the files of x.y two directories up
_py_relmod(path, d, mod) := {c |
	dparts := _dir_parts(path)
	n := count(dparts) - (d - 1)
	n >= 0
	b := concat("/", array.concat(array.slice(dparts, 0, n), split(mod, ".")))
	some suffix in [".py", "/__init__.py"]
	c := concat("", [b, suffix])
	input.file_set[c]
}

# `from . import name`: the submodule `name` when it exists, else the package
_py_relname(path, d, name) := subs if {
	subs := _py_relmod(path, d, name)
	count(subs) > 0
}

_py_relname(path, d, name) := {c} if {
	count(_py_relmod(path, d, name)) == 0
	dparts := _dir_parts(path)
	n := count(dparts) - (d - 1)
	n >= 0
	c := concat("", [_root(dparts, n), "__init__.py"])
	input.file_set[c]
}

_py_t_import(imp) := {c |
	startswith(imp.text, "import ")
	some part in split(substring(imp.text, 7, -1), ",")
	words := split(trim_space(part), " ")
	mod := words[0]
	regex.match(`^[A-Za-z_][\w\.]*$`, mod)
	some c in _py_abs(imp.path, imp.rel, mod)
}

# the names after `import` in a from-import, `*` included
_py_names(text) := [n |
	m := regex.find_all_string_submatch_n(`\simport\s+(.*)$`, text, 1)
	raw := regex.replace(regex.replace(m[0][1], `#.*$`, ""), `[()]`, "")
	some part in split(raw, ",")
	n := split(trim_space(part), " ")[0]
	n != ""
]

# `from pkg import sub` loads the submodule sub when there is one; any other
# name is an attribute of pkg itself
_py_t_from_abs(imp) := {c |
	m := regex.find_all_string_submatch_n(`^from\s+([A-Za-z_][\w\.]*)\s+import\s`, imp.text, 1)
	count(m) > 0
	mod := m[0][1]
	some name in _py_names(imp.text)
	some c in _py_abs_name(imp.path, imp.rel, mod, name)
}

_py_abs_name(path, rel, mod, name) := subs if {
	regex.match(`^[A-Za-z_]\w*$`, name)
	subs := _py_abs(path, rel, concat(".", [mod, name]))
	count(subs) > 0
} else := _py_abs(path, rel, mod)

_py_t_from_rel(imp) := {c |
	m := regex.find_all_string_submatch_n(`^from\s+(\.+)([A-Za-z_][\w\.]*)\s+import\s`, imp.text, 1)
	count(m) > 0
	d := count(m[0][1])
	mod := m[0][2]
	some name in _py_names(imp.text)
	some c in _py_rel_name(imp.path, d, mod, name)
}

_py_rel_name(path, d, mod, name) := subs if {
	regex.match(`^[A-Za-z_]\w*$`, name)
	subs := _py_relmod(path, d, concat(".", [mod, name]))
	count(subs) > 0
} else := _py_relmod(path, d, mod)

_py_t_from_dot(imp) := {c |
	m := regex.find_all_string_submatch_n(`^from\s+(\.+)\s+import\s`, imp.text, 1)
	count(m) > 0
	some name in _py_names(imp.text)
	regex.match(`^[A-Za-z_]\w*$`, name)
	some c in _py_relname(imp.path, count(m[0][1]), name)
}

_edges contains e if {
	some imp in _py_imports
	targets := ((_py_t_import(imp) | _py_t_from_abs(imp)) | _py_t_from_rel(imp)) | _py_t_from_dot(imp)
	some to in targets
	to != imp.path
	e := {"from": imp.path, "to": to, "i": imp.i, "line": imp.line, "kind": imp.kind}
}

# ── JavaScript / TypeScript ───────────────────────────────────────────────

_js_exts := [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]

_is_js(path) if {
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".d.ts")
}

_js_spec := `['"](\.\.?/[^'"]*|\.\.?)['"]`

_js_comment(t) if startswith(t, "//")

_js_comment(t) if startswith(t, "*")

_js_comment(t) if startswith(t, "/*")

# [specifier, kind, index of the statement's first line]
_js_r_require(_, i, line, t) := {[s, k, i] |
	m := regex.find_all_string_submatch_n(concat("", [`\brequire\(\s*`, _js_spec, `\s*\)`]), line, -1)
	some x in m
	s := x[1]
	_js_outside_string(line, x[0])
	k := _js_require_kind(line)
}

# the call is code, not text inside a string literal: an even number of each
# quote character precedes it
_js_outside_string(line, call) if {
	prefix := substring(line, 0, indexof(line, call))
	strings.count(prefix, `"`) % 2 == 0
	strings.count(prefix, "'") % 2 == 0
	strings.count(prefix, "`") % 2 == 0
}

_js_r_dynamic(_, i, line, _) := {[s, "deferred", i] |
	m := regex.find_all_string_submatch_n(concat("", [`\bimport\(\s*`, _js_spec, `\s*\)`]), line, -1)
	some x in m
	s := x[1]
	_js_outside_string(line, x[0])
}

_js_r_from(_, i, _, t) := {[s, "module", i] |
	regex.match(`^(import|export)\b`, t)
	not _js_type_only(t)
	m := regex.find_all_string_submatch_n(concat("", [`\bfrom\s*`, _js_spec]), t, 1)
	some x in m
	s := x[1]
}

_js_r_side(_, i, _, t) := {[s, "module", i] |
	m := regex.find_all_string_submatch_n(concat("", [`^import\s*`, _js_spec]), t, 1)
	some x in m
	s := x[1]
}

# the closing line of a multi-line import/export list
_js_r_close(lines, i, _, t) := {[s, "module", j] |
	startswith(t, "}")
	m := regex.find_all_string_submatch_n(concat("", [`^\}\s*from\s*`, _js_spec]), t, 1)
	some x in m
	s := x[1]
	starts := [k | some k in numbers.range(max([0, i - 40]), i - 1); regex.match(`^\s*(import|export)\b`, lines[k])]
	count(starts) > 0
	j := starts[count(starts) - 1]
	not _js_type_only(trim_left(lines[j], " \t"))
}

# a top-level require runs at load; one inside a function body is deferred
_js_require_kind(line) := "module" if _indent(line) == 0

_js_require_kind(line) := "deferred" if _indent(line) > 0

_js_type_only(t) if regex.match(`^(import|export)\s+type\b`, t)

_js_type_only(t) if {
	m := regex.find_all_string_submatch_n(`^import\s*\{([^}]*)\}\s*from`, t, 1)
	count(m) > 0
	names := [n | some p in split(m[0][1], ","); n := trim_space(p); n != ""]
	count(names) > 0
	every n in names {
		startswith(n, "type ")
	}
}

_js_resolve(path, spec) := c if {
	dparts := _dir_parts(path)
	sparts := [p | some p in split(spec, "/"); p != "."; p != ""]
	ups := count([p | some p in sparts; p == ".."])
	count([k | some k, p in sparts; p == ".."; k >= ups]) == 0
	n := count(dparts) - ups
	n >= 0
	rest := array.slice(sparts, ups, count(sparts))
	root := _root(dparts, n)
	cand_list := array.concat(array.concat(_js_cand_file(root, rest), _js_cand_ts(root, rest)), _js_cand_index(root, rest))
	cands := [x | some x in cand_list; input.file_set[x]]
	count(cands) > 0
	c := cands[0]
}

_js_cand_file(root, rest) := [x |
	count(rest) > 0
	b := concat("", [root, concat("/", rest)])
	some suffix in ["", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts", "/index.js", "/index.ts", "/index.tsx", "/index.jsx", "/index.mjs"]
	x := concat("", [b, suffix])
]

# `./x.js` written in TypeScript source names `./x.ts`
_js_cand_ts(root, rest) := [x |
	count(rest) > 0
	b := concat("", [root, concat("/", rest)])
	some pair in [[".js", ".ts"], [".js", ".tsx"], [".mjs", ".mts"], [".cjs", ".cts"]]
	endswith(b, pair[0])
	x := concat("", [substring(b, 0, count(b) - count(pair[0])), pair[1]])
]

_js_cand_index(root, rest) := [x |
	count(rest) == 0
	some suffix in ["index.js", "index.ts", "index.tsx", "index.jsx", "index.mjs"]
	x := concat("", [root, suffix])
]

_edges contains e if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "./")
	not _vendored(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "./")
	t := trim_left(line, " \t")
	not _js_comment(t)
	refs := (((_js_r_require(lines, i, line, t) | _js_r_dynamic(lines, i, line, t)) | _js_r_from(lines, i, line, t)) | _js_r_side(lines, i, line, t)) | _js_r_close(lines, i, line, t)
	some ref in refs
	to := _js_resolve(path, ref[0])
	to != path
	e := {"from": path, "to": to, "i": ref[2], "line": lines[ref[2]], "kind": ref[1]}
}

# ── cycles ────────────────────────────────────────────────────────────────

# load-time import graph: module -> the modules it imports when loaded
_out[a] contains b if {
	some e in _edges
	e.kind == "module"
	a := e.from
	b := e.to
}

# graph.reachable only walks through nodes that are keys of the graph, so every
# imported module gets an entry, empty when it imports nothing
_graph := {n: object.get(_out, n, set()) | some e in _edges; e.kind == "module"; some n in [e.from, e.to]}

_line_of(a, b) := min({e.i | some e in _edges; e.from == a; e.to == b; e.kind == "module"}) + 1

_finding(e, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": e.from,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": e.i + 1,
	"snippet": e.line,
}

# two modules import each other at load time: reported once, in the file whose
# path sorts first
findings contains _finding(e, msg) if {
	some e in _edges
	e.kind == "module"
	e.from < e.to
	_out[e.to][e.from]
	msg := sprintf("Circular dependency: this module imports %s, which imports this module back at line %d. Whichever loads first sees the other only partially initialised; move the shared code into a third module or invert one dependency", [e.to, _line_of(e.to, e.from)])
}

# three modules in a load-time cycle: reported once, on the import made by the
# module whose path sorts first
findings contains _finding(e, msg) if {
	some e in _edges
	e.kind == "module"
	a := e.from
	b := e.to
	a < b
	not _out[b][a]
	thirds := sort([c | some c in _out[b]; c != a; a < c; _out[c][a]])
	count(thirds) > 0
	c := thirds[0]
	msg := sprintf("Circular dependency: this module imports %s, which imports %s, which imports this module back at line %d. Whichever loads first sees the others only partially initialised; move the shared code into a separate module or invert one dependency", [b, c, _line_of(c, a)])
}

# an import inside a function that closes a cycle with load-time imports (of
# any length) back to this module: the cycle is real, only hidden
findings contains _finding(e, msg) if {
	some e in _edges
	e.kind == "deferred"
	e.from in graph.reachable(_graph, {e.to})
	msg := sprintf("Circular dependency hidden by a deferred import: this function imports %s, which imports this module at load time (directly or through other modules). Break the cycle instead of importing inside a function", [e.to])
}
