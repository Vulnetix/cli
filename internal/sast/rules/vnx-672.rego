# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_672

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-672",
	"name": "Operation on a file, socket, stream or connection after it was closed",
	"description": "A resource is used after the code itself released it, in straight-line code of the same block. Python: X.close() (or os.close(fd)) followed within 15 lines by X.read/readline/readlines/write/writelines/seek/tell/truncate/flush, X.send/sendall/sendto/recv/recvfrom, X.execute/executemany/executescript/cursor/commit/fetchone/fetchall/fetchmany (or os.read/os.write/os.fstat/os.lseek on the fd), including a cursor whose connection was closed; and a 'with ... as X:' block followed, after it ends, by such a call on X. Node.js/TypeScript: X.end(), X.close(), X.destroy() or X.release() followed by X.write/read/query/execute/run/all/get/exec/prepare/send/push/each, and fs.close/closeSync(fd) followed by fs.read/write/fstat(Sync)(fd, ...). The call raises ValueError/'write after end'/'Client was released' or silently operates on a dead or recycled handle. Not reported: a reassignment or re-open of the variable in between, any return/raise/throw/break/continue/def/function boundary or end of the enclosing block between the release and the use (a close in an error branch or another method), attribute checks such as f.closed, event listeners (stream.on('finish')) after end(), HTTP responses (res.end(), covered by VNX-666), comments, docstrings and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-672/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [672],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["expired-resource-use", "cwe-672", "use-after-close"],
}

_js_exts := [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

_py_ops := `read|readline|readlines|write|writelines|seek|tell|truncate|flush|send|sendall|sendto|recv|recvfrom|execute|executemany|executescript|cursor|commit|fetchone|fetchall|fetchmany`

_js_ops := `write|read|query|execute|run|all|get|exec|prepare|send|push|each`

_ident := `[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`

_esc(x) := replace(replace(x, ".", `\.`), "$", `\$`)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── releases: (kind, receiver) at line i ─────────────────────────────────

_release(lang, line) := ["obj", x] if {
	lang == "py"
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(`, _ident, `)\.close\(\)\s*(?:#.*)?$`]), line, 1)
	x := m[0][1]
	x != "os"
}

_release(lang, line) := ["fd", m[0][1]] if {
	lang == "py"
	m := regex.find_all_string_submatch_n(`^\s*os\.close\(\s*([A-Za-z_]\w*)\s*\)\s*$`, line, 1)
}

_release(lang, line) := ["obj", x] if {
	lang == "js"
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:await\s+)?(`, _ident, `)\.(?:end|close|destroy|release)\(\)\s*;?\s*$`]), line, 1)
	x := m[0][1]
	not regex.match(`^(?:res|response|reply|resp|req|request|ctx|ctx\.res|this\.res)$`, x)
	not regex.match(`^(?:fs|console|process)$`, x)
}

_release(lang, line) := ["fd", m[0][1]] if {
	lang == "js"
	m := regex.find_all_string_submatch_n(`^\s*(?:await\s+)?fs\.close(?:Sync)?\(\s*([A-Za-z_$][\w$]*)\s*[,)]`, line, 1)
}

# ── uses of a released receiver ──────────────────────────────────────────

_use(lang, "obj", x, line) if {
	ops := {"py": _py_ops, "js": _js_ops}[lang]
	regex.match(concat("", [`(?:^|[^\w$.])`, _esc(x), `\.(?:`, ops, `)\(`]), _strip(line))
}

_use("py", "fd", x, line) if regex.match(concat("", [`\bos\.(?:read|write|fstat|lseek|fsync)\(\s*`, x, `\s*[,)]`]), _strip(line))

_use("js", "fd", x, line) if regex.match(concat("", [`\bfs\.(?:read|write|fstat|fsync|ftruncate)(?:Sync)?\(\s*`, _esc(x), `\s*[,)]`]), _strip(line))

# String literals blanked, so a call spelled inside one is not a use.
_strip(s) := regex.replace(regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`), "`(?:[^`\\\\]|\\\\.)*`", "``")

# A cursor of a closed connection: `cur = conn.cursor()` above the close.
_dependents(lines, i, "obj", x) := {c |
	some j in numbers.range(max([0, i - 15]), i - 1)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*([A-Za-z_]\w*)\s*=\s*`, _esc(x), `\.cursor\(`]), lines[j], 1)
	c := m[0][1]
}

_dependents(_, _, "fd", _) := set()

# ── the straight-line region after a release ─────────────────────────────

_barrier := `^\s*(?:def\s|class\s|async\s+def\s|return\b|raise\b|break\b|continue\b|throw\b|function\b|async\s+function\b|\}|else\b|elif\b|except\b|finally\b|catch\b|case\b|default\s*:)`

_stops(lines, j, ind, x) if _indent(lines[j]) < ind

_stops(lines, j, _, _) if regex.match(_barrier, lines[j])

_stops(lines, j, _, x) if regex.match(concat("", [`^\s*(?:(?:const|let|var)\s+)?`, _esc(x), `\s*(?::[^=]*)?=[^=]`]), lines[j])

_stops(lines, j, _, x) if regex.match(concat("", [`\bas\s+`, _esc(x), `\s*[:,)]`]), lines[j])

_code(line) if {
	trim_space(line) != ""
	not helpers.is_comment_line(line)
}

# Last line index (exclusive) of the region after line i.
_region_end(lines, i, ind, x) := e if {
	last := min([count(lines) - 1, i + 15])
	stops := [j |
		some j in numbers.range(i + 1, last)
		_code(lines[j])
		_stops(lines, j, ind, x)
	]
	e := min(array.concat([last + 1], stops))
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in _js_exts
	endswith(path, ext)
}

_in_docstring(lines, i) if {
	before := [l | some j in numbers.range(max([0, i - 60]), i - 1); l := lines[j]]
	n := sum([c | some l in before; c := strings.count(l, `"""`) + strings.count(l, `'''`)])
	n % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(`(?m)(?:(?:\.close\(\)|\.end\(\)|\.destroy\(\)|\.release\(\))\s*;?\s*$|\bos\.close\(|\bfs\.close(?:Sync)?\()`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:close|end|destroy|release)(?:Sync)?\(`, line)
	r := _release(lang, line)
	kind := r[0]
	x := r[1]
	not _in_docstring(lines, i)
	ind := _indent(line)
	e := _region_end(lines, i, ind, x)
	i + 1 <= e - 1
	names := {x} | _dependents(lines, i, kind, x)
	some j in numbers.range(i + 1, e - 1)
	_code(lines[j])
	some name in names
	_use(lang, kind, name, lines[j])
	finding := _finding(path, j, lines[j], sprintf("'%s' is used here after it was released on line %d; the call fails or operates on a dead handle. Move the release after the last use", [name, i + 1]))
}

# `with ... as X:` — X is closed once the block ends.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*with\s.*\bas\s+[A-Za-z_]\w*\s*:\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_left(line, " \t"), "with ")
	m := regex.find_all_string_submatch_n(`^\s*with\s+(?:open|io\.open|socket\.\w+|sqlite3\.connect|closing)\(.*\bas\s+([A-Za-z_]\w*)\s*:\s*$`, line, 1)
	x := m[0][1]
	not _in_docstring(lines, i)
	ind := _indent(line)
	k := _block_end(lines, i, ind)
	_indent(lines[k]) == ind
	e := _region_end(lines, k - 1, ind, x)
	k <= e - 1
	some j in numbers.range(k, e - 1)
	_code(lines[j])
	_use("py", "obj", x, lines[j])
	finding := _finding(path, j, lines[j], sprintf("'%s' was closed when the 'with' block on line %d ended; this call fails with 'I/O operation on closed file'. Move it inside the block", [x, i + 1]))
}

# First code line after the with-header that is not deeper than the header.
_block_end(lines, i, ind) := k if {
	last := min([count(lines) - 1, i + 80])
	cands := [j |
		some j in numbers.range(i + 1, last)
		_code(lines[j])
		_indent(lines[j]) <= ind
	]
	count(cands) > 0
	k := cands[0]
}

_finding(path, j, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": j + 1,
	"snippet": line,
}
