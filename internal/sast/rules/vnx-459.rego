# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_459

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-459",
	"name": "Incomplete Cleanup",
	"description": "Python code that creates a temporary directory or file which is never removed: tempfile.mkdtemp(), tempfile.mkstemp() or tempfile.NamedTemporaryFile(..., delete=False) (any module alias or a from-import) whose result is assigned to a name, attribute or `with ... as` target that no shutil.rmtree / os.remove / os.unlink / os.rmdir / Path(...).unlink / .cleanup / atexit.register / addCleanup call in the same file ever receives, or that is created inline in a file with no removal call at all. The temporary data outlives the process and accumulates on disk with whatever it contained. Not reported: TemporaryDirectory() and NamedTemporaryFile() with the default delete=True, a result that is returned, yielded or stored into a collection or attribute (the caller owns the cleanup), cleanup in a finally block, close() or tearDown method of the same file, test files, comments and string literals. Cleanup in another file is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-459/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [459],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-cleanup", "cwe-459"],
}

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|#.*$`, `""`)

_mk_re := `(?:^|[^\w.])(?:[A-Za-z_]\w*\.)?(mkdtemp|mkstemp)\s*\(`

_ntf_re := `(?:^|[^\w.])(?:[A-Za-z_]\w*\.)?NamedTemporaryFile\s*\(`

# kind of temporary object created on line i
_creates(_, _, l, _) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_mk_re, l, 1)
	count(m) > 0
}

_creates(lines, i, l, _) := "ntf" if {
	regex.match(_ntf_re, l)
	_delete_false(lines, i, "NamedTemporaryFile")
}

# `from tempfile import mkdtemp as make_tmp`: the alias creates the same thing.
_creates(lines, i, l, al) := kind if {
	some a, k in al
	regex.match(concat("", [`(?:^|[^\w.])`, a, `\s*\(`]), l)
	kind := _alias_kind(lines, i, a, k)
}

_alias_kind(_, _, _, k) := k if k != "NamedTemporaryFile"

_alias_kind(lines, i, a, "NamedTemporaryFile") := "ntf" if _delete_false(lines, i, a)

_delete_false(lines, i, fn) if {
	w := concat(" ", [_strip(lines[k]) | some k in numbers.range(i, min([count(lines) - 1, i + 3]))])
	regex.match(concat("", [fn, `\s*\([^)]*\bdelete\s*=\s*False`]), w)
}

_aliases(content) := {} if not contains(content, " as ")

_aliases(content) := {m[2]: m[1] |
	some m in regex.find_all_string_submatch_n(`\b(mkdtemp|mkstemp|NamedTemporaryFile)\s+as\s+([A-Za-z_]\w*)`, content, -1)
} if contains(content, " as ")

_candidate(line, _) if regex.match(`mk[sd]temp|NamedTemporaryFile`, line)

_candidate(line, al) if {
	some a, _ in al
	contains(line, a)
}

# The name that holds the temporary path.
_holder(l, kind) := v if {
	kind == "mkstemp"
	m := regex.find_all_string_submatch_n(`^\s*(?:[A-Za-z_][\w.]*\s*,\s*)+([A-Za-z_][\w.]*)\s*=[^=]`, l, 1)
	count(m) > 0
	v := m[0][1]
}

_holder(l, kind) := v if {
	not regex.match(`^\s*[\w.]+\s*,`, l)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][\w.]*)\s*(?::\s*[\w.\[\]]+\s*)?=[^=]`, l, 1)
	count(m) > 0
	v := m[0][1]
}

_holder(l, _) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?with\b.*\bas\s+([A-Za-z_]\w*)\s*:`, l, 1)
	count(m) > 0
	v := m[0][1]
}

_has_holder(l, kind) if _holder(l, kind)

_esc(v) := replace(v, ".", `\.`)

_cleanup_call := `(?:rmtree|unlink|remove|rmdir|removedirs|cleanup|replace|rename|move|register|addCleanup|addFinalizer|callback)\s*\(\s*(?:[\w.]+\(\s*)?`

_cleaned(content, v) if regex.match(concat("", [_cleanup_call, _esc(v), `\b`]), content)

_cleaned(content, v) if regex.match(concat("", [`\(\s*`, _esc(v), `(?:\.name)?\s*\)\s*\.(?:unlink|rmdir|cleanup)\s*\(|\b`, _esc(v), `\.cleanup\s*\(`]), content)

# A cleanup registered with the function first and the path as an argument:
# atexit.register(shutil.rmtree, d), stack.callback(os.remove, p),
# weakref.finalize(self, shutil.rmtree, d).
_cleaned(content, v) if regex.match(concat("", [`\b(?:register|callback|finalize|addCleanup|addFinalizer|push)\s*\([^\n]*?[(,]\s*`, _esc(v), `(?:\.name)?\b`]), content)

# ownership handed on: returned, yielded, collected or stored.
_escapes(content, v) if regex.match(concat("", [`(?m)^\s*(?:return|yield)\s+(?:[^\n#]*,\s*)?[(\[]?\s*`, _esc(v), `\s*(?:[,)\]]|$)`]), content)

_escapes(content, v) if regex.match(concat("", [`\.(?:append|add|extend|put|insert)\(\s*`, _esc(v), `\b|(?:self|cls)\.\w+\s*=\s*`, _esc(v), `\b|\[[^\]\n]*\]\s*=\s*`, _esc(v), `\b`]), content)

_report(content, l, kind) if {
	v := _holder(l, kind)
	not _cleaned(content, v)
	not _escapes(content, v)
}

_report(content, l, kind) if {
	not _has_holder(l, kind)
	not regex.match(`^\s*(?:return|yield)\b|\b(?:append|add|extend|insert)\s*\(`, l)
	not regex.match(`\b(?:rmtree|unlink|remove|rmdir|cleanup|register|addCleanup)\s*\(`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`mkdtemp|mkstemp|delete\s*=\s*False`, content)
	lines := split(content, "\n")
	al := _aliases(content)
	some i, line in lines
	_candidate(line, al)
	not helpers.is_comment_line(line)
	l := _strip(line)
	some kind in {_creates(lines, i, l, al)}
	_report(content, l, kind)
	finding := {
		"rule_id": metadata.id,
		"message": "Temporary file or directory is created but never removed; use tempfile.TemporaryDirectory()/NamedTemporaryFile() as a context manager, or remove it in a finally block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
