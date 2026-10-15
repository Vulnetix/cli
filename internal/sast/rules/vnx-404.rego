# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_404

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-404",
	"name": "Improper Resource Shutdown or Release",
	"description": "Reports a file or database handle bound to a local variable inside a function and never released on any path before the function ends. Python: `x = open(...)` (also io.open, codecs.open, gzip/bz2/lzma.open) with no `x.close()`, `with x`, `contextlib.closing(x)`, `enter_context(x)`, and where x is not returned, yielded, stored on an object or in a collection. Java: a local assigned `new FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile/ZipFile/JarFile(...)` (possibly wrapped, `new BufferedReader(new FileReader(p))`) , `Files.newBufferedReader/newBufferedWriter/newInputStream/newOutputStream(...)` or `DriverManager.getConnection(...)`, outside try-with-resources, with no `x.close()`/`closeQuietly(x)` and not returned, stored in a field or handed to another constructor. Not reported: a release in finally, module-level (script) opens, a handle chained in place (`open(p).read()`), test files, comments and strings. A handle that is closed only on the success path (no try/finally) is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-404/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [404],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["resource-release", "cwe-404"],
}

_indent(l) := count(l) - count(trim_left(l, " \t"))

_blank(l) if trim_space(l) == ""

# ── Python ───────────────────────────────────────────────────────────────

_py_open_re := `^(\s+)([A-Za-z_]\w*)\s*=\s*(?:io\.|codecs\.|gzip\.|bz2\.|lzma\.)?open\(`

# open(p).read(): the handle is a temporary, not the variable.
_py_chained(l) if regex.match(`open\([^()]*(\([^()]*\)[^()]*)*\)\s*\.\w`, l)

_py_released(l, v) if regex.match(concat("", [`\b`, v, `\.(close|__exit__)\b`]), l)

_py_released(l, v) if regex.match(concat("", [`\b(with|async\s+with)\s+`, v, `\b`]), l)

_py_released(l, v) if regex.match(concat("", [`\b(closing|enter_context|push)\(\s*`, v, `\s*\)`]), l)

_py_released(l, v) if regex.match(concat("", [`^\s*(return|yield(\s+from)?)\s+(\(?\s*|[A-Z][\w.]*\(\s*)`, v, `\s*(\)\s*)?(,.*|#.*)?$`]), l)

_py_released(l, v) if regex.match(concat("", [`[\w\]\)]\s*=\s*`, v, `\s*(#.*)?$`]), l)

_py_released(l, v) if regex.match(concat("", [`\.(append|add|insert|extend|setdefault|put)\([^)]*\b`, v, `\s*\)`]), l)

# The end of the enclosing function: a def/class at a shallower indent or
# module-level code.
_py_end(lines, i, ind) := e if {
	hi := min([count(lines), i + 80])
	ends := [k |
		some k in numbers.range(i + 1, hi - 1)
		l := lines[k]
		not _blank(l)
		_py_leaves(l, ind)
	]
	e := min(array.concat([hi], ends))
}

_py_leaves(l, _) if {
	_indent(l) == 0
	not startswith(l, "#")
}

_py_leaves(l, ind) if {
	_indent(l) < ind
	regex.match(`^\s*(async\s+def|def|class)\s`, l)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "open(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "open(")
	m := regex.find_all_string_submatch_n(_py_open_re, line, 1)
	count(m) > 0
	not _py_chained(line)
	v := m[0][2]
	ind := count(m[0][1])
	e := _py_end(lines, i, ind)
	not _py_any_release(lines, i, e, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is opened here and never closed before the function ends: the file descriptor stays open until garbage collection. Use `with open(...) as %s:`.", [v, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_py_any_release(lines, i, e, v) if {
	some k in numbers.range(i + 1, e - 1)
	k < e
	contains(lines[k], v)
	_py_released(lines[k], v)
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_open_re := `^(\s*)(?:final\s+)?([A-Z][\w.<>\[\]]*\s+)?([a-z_]\w*)\s*=\s*(?:\([\w.]+\)\s*)?(?:new\s+(?:[\w.]+\s*\(\s*new\s+)*(?:java\.io\.)?(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|ZipFile|JarFile)\s*\(|DriverManager\s*\.\s*getConnection\s*\(|(?:java\.nio\.file\.)?Files\s*\.\s*new(?:BufferedReader|BufferedWriter|InputStream|OutputStream)\s*\()`

_java_released(l, v) if regex.match(concat("", [`\b`, v, `\s*\.\s*close\s*\(`]), l)

_java_released(l, v) if regex.match(concat("", [`close\w*\s*\(\s*`, v, `\s*[,)]`]), l)

_java_released(l, v) if regex.match(concat("", [`\breturn\s+(\([^()]*\)\s*)?`, v, `\s*;`]), l)

_java_released(l, v) if regex.match(concat("", [`=\s*`, v, `\s*;`]), l)

_java_released(l, v) if regex.match(concat("", [`\bnew\s+[\w.<>]+\s*\([^;]*\b`, v, `\b`]), l)

_java_released(l, v) if regex.match(concat("", [`\btry\s*\(\s*`, v, `\s*[;)]`]), l)

_java_released(l, v) if regex.match(concat("", [`\.(add|put|push|offer|register)\s*\([^;]*\b`, v, `\s*\)`]), l)

# Inside a try-with-resources header (single or multi-line).
_java_twr(lines, i) if regex.match(`\btry\s*\(`, lines[i])

_java_twr(lines, i) if {
	some j in numbers.range(max([0, i - 4]), i - 1)
	j < i
	regex.match(`\btry\s*\(`, lines[j])
	not _java_brace_between(lines, j, i)
}

_java_brace_between(lines, j, i) if {
	some k in numbers.range(j, i - 1)
	contains(lines[k], "{")
}

# A bare `x = new FileInputStream(f)` is a local only when x was declared in
# the method a few lines above; otherwise it is a field.
_java_local(m, _, _, _) if m[0][2] != ""

_java_local(m, lines, i, v) if {
	m[0][2] == ""
	some j in numbers.range(max([0, i - 20]), i - 1)
	j < i
	regex.match(concat("", [`^\s+(final\s+)?[A-Z][\w.<>\[\]]*\s+`, v, `\s*(=\s*null\s*)?;`]), lines[j])
}

_java_end(lines, i, ind) := e if {
	hi := min([count(lines), i + 80])
	ends := [k |
		some k in numbers.range(i + 1, hi - 1)
		l := lines[k]
		_indent(l) < ind
		regex.match(`^\s*((public|private|protected|static)\s[^;=]*\(|\}\s*$)`, l)
		_java_method_end(l, ind)
	]
	e := min(array.concat([hi], ends))
}

# A method declaration below, or the closing brace of the method itself
# (indent at least two levels shallower is the class).
_java_method_end(l, _) if regex.match(`^\s*(public|private|protected|static)\s`, l)

_java_method_end(l, ind) if {
	regex.match(`^\s*\}\s*$`, l)
	_indent(l) <= ind - 8
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`new\s+(java\.io\.)?(File|RandomAccessFile|ZipFile|JarFile)|getConnection|Files\s*\.\s*new(BufferedReader|BufferedWriter|InputStream|OutputStream)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`File|getConnection`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_java_open_re, line, 1)
	count(m) > 0
	v := m[0][3]
	_java_local(m, lines, i, v)
	not _java_twr(lines, i)
	ind := count(m[0][1])
	e := _java_end(lines, i, ind)
	not _java_any_release(lines, i, e, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is opened here and never closed before the method ends, so the handle leaks. Open it in a try-with-resources statement: try (... %s = ...) { ... }.", [v, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_java_any_release(lines, i, e, v) if {
	some k in numbers.range(i + 1, e - 1)
	k < e
	contains(lines[k], v)
	_java_released(lines[k], v)
}
