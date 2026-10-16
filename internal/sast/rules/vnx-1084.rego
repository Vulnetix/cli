# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1084

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1084",
	"name": "Invokable Control Element with Excessive File or Data Access Operations",
	"description": "A Python function or method whose own body performs more than 7 file or data access operations: `open(...)` and `x.open(...)` (io, gzip, tarfile, aiofiles, Path), cursor/connection `.execute(...)`/`.executemany(...)`/`.executescript(...)` with an argument, `os.remove/unlink/rename/replace/makedirs/mkdir/rmdir/removedirs/chmod/chown/listdir/scandir/symlink/link/truncate`, `shutil.copy*/move/rmtree`, and pathlib `read_text/write_text/read_bytes/write_bytes/unlink/rmdir/mkdir/touch`. A function that does that much I/O mixes several responsibilities, which makes its error handling and its authorisation of each access hard to review. One finding per function, at its `def` line. Operations are counted per source line, inside the function's indented body (bounded to 400 lines), and nested functions count toward the enclosing one. Not reported: functions with 7 operations or fewer, operations named in comments, string literals or doctest (`>>>`) lines, command-pattern calls with no argument (`step.execute()`), `webbrowser.open(...)` and argument-less `self.<widget>.open()`, and test files. The threshold is this rule's choice; CWE-1084 does not fix one.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1084/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1084],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["invokable-element-excessive-file-operations", "maintainability", "cwe-1084"],
}

_max_ops := 7

_max_body_lines := 400

_op_re := `(?:^|[^\w.])open\s*\(|\.\s*open\s*\(|\.(?:execute|executemany|executescript)\s*\(\s*(?:[^\s)]|$)|\bos\.(?:remove|rename|replace|makedirs|removedirs|chmod|chown|listdir|scandir|symlink|link|truncate)\s*\(|\bshutil\.(?:copy|copy2|copyfile|copyfileobj|copytree|move|rmtree)\s*\(|\.(?:read_text|write_text|read_bytes|write_bytes|touch|unlink|mkdir|rmdir)\s*\(`

# Calls that look like an operation but are not file or data access: opening a
# browser tab or a UI widget (`self.dialog.open()`), and doctest examples.
_not_op(line) if regex.match(`\bwebbrowser\.open|\bself(?:\.\w+)+\.open\s*\(\s*\)|^\s*(?:>>>|\.\.\.\s)`, line)

_def_re := `^(\s*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(`

_strip_literals(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_is_code(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

# Index one past the last line of the body of the def at i.
_body_end(lines, i, ind) := e if {
	limit := min([count(lines) - 1, i + _max_body_lines])
	outs := [k |
		some k in numbers.range(i + 1, limit)
		_is_code(lines[k])
		_indent(lines[k]) <= ind
		not regex.match(`^\s*[)\]}]`, lines[k])
	]
	e := _first_or(outs, limit + 1)
}

_first_or(xs, d) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_is_op(line) if {
	_is_code(line)
	not _not_op(line)
	regex.match(_op_re, _strip_literals(line))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(concat("", ["(?m)", _op_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_def_re, line)
	ind := _indent(line)
	e := _body_end(lines, i, ind)
	e > i + _max_ops
	n := count([k | some k in helpers.span(i + 1, e - 1); _is_op(lines[k])])
	n > _max_ops
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function performs %d file or data access operations (limit %d); split the I/O into smaller functions with one responsibility each", [n, _max_ops]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
