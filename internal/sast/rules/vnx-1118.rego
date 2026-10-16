# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1118

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1118",
	"name": "Insufficient Documentation of Error Handling Techniques",
	"description": "A Python function whose docstring documents its interface in sections (Google style Args:/Returns:, NumPy style Parameters/Returns underlined, or Sphinx :param/:returns: fields) but leaves out the exceptions: the function raises a named exception itself (raise ValueError(...), raise errors.AuthError) and its docstring has no Raises section, :raises: field or mention of that exception. Reported once per function, on the first such raise. Not reported: a bare re-raise (raise) or re-raise of a caught exception value (raise exc, raise last_error), raise SystemExit/KeyboardInterrupt/GeneratorExit, raise NotImplementedError (an abstract method), functions with no docstring or a one-line summary only (the project does not document arguments, so a missing Raises section is not an omission from a documented contract), raises inside a nested function, test files, and comments. CWE-1118 is a maintainability weakness: callers of the function are not told which errors to handle.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1118/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1118],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-error-docs", "cwe-1118", "maintainability"],
}

_raise_re := `^(\s*)raise\s+((?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*))\s*(?:\(|$|\s+from\b)`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_is_code(line) if {
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
}

_def_line(line) if regex.match(`^\s*(?:async\s+)?def\s+[A-Za-z_]`, line)

# Nearest def above the raise that encloses it: less indented than the raise,
# with no code between them at or left of the def's own indent.
_enclosing_def(lines, i, ri) := d if {
	cands := [k |
		some k in numbers.range(max([0, i - 200]), i - 1)
		_def_line(lines[k])
		_indent(lines[k]) < ri
	]
	count(cands) > 0
	d := max(cands)
	di := _indent(lines[d])
	e := _sig_end(lines, d)
	e < i
	not _breaks_out(lines, e, i, di)
}

_breaks_out(lines, e, i, di) if {
	some k in helpers.span(e + 1, i - 1)
	_is_code(lines[k])
	_indent(lines[k]) <= di
}

_sig_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 15])
	cands := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(#.*)?$`, lines[k])
	]
	count(cands) > 0
	e := cands[0]
}

# The docstring text, from its opening triple quote to its closing one.
_docstring(lines, d) := txt if {
	e := _sig_end(lines, d)
	b := helpers.next_code_index(lines, e, 4)
	m := regex.find_all_string_submatch_n(`^\s*[rRuU]?("""|''')`, lines[b], 1)
	count(m) > 0
	q := m[0][1]
	end := min([count(lines) - 1, b + 120])
	closers := [k |
		some k in numbers.range(b, end)
		_closes(lines[k], q, k == b)
	]
	count(closers) > 0
	txt := concat("\n", array.slice(lines, b, closers[0] + 1))
}

_closes(line, q, false) if contains(line, q)

_closes(line, q, true) if {
	parts := split(line, q)
	count(parts) >= 3
}

_sectioned(doc) if regex.match(`(?m)^\s*(?:Args|Arguments|Parameters|Params|Returns|Return|Yields|Keyword Args)\s*:?\s*$`, doc)

_sectioned(doc) if regex.match(`(?m)^\s*:(?:param|type|returns?|rtype)\b`, doc)

_documents_errors(doc, _) if regex.match(`(?i)\braise[sd]?\b|:except\b|\bthrows?\b|\bexceptions?\s*:`, doc)

_documents_errors(doc, exc) if contains(doc, exc)

_exempt_exc("NotImplementedError")

_exempt_exc("StopIteration")

_exempt_exc("StopAsyncIteration")

# Process exits and interpreter control flow, not errors for a caller to
# handle.
_exempt_exc("SystemExit")

_exempt_exc("KeyboardInterrupt")

_exempt_exc("GeneratorExit")

# raise exc / raise last: re-raising an exception value caught or stored
# earlier (a lower-case plain name, not called), which propagates an error
# rather than raising a new one, like a bare raise.
_reraise_value(line) if regex.match(`^\s*raise\s+[a-z_][a-z0-9_]*\s*(?:#.*)?$`, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*raise\s+[A-Za-z_]`, content)
	regex.match(`(?m)^\s*(?:Args|Arguments|Parameters|Returns|Return)\s*:?\s*$|^\s*:(?:param|returns?|rtype)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_raise_re, line, 1)
	count(m) > 0
	exc := m[0][3]
	not _exempt_exc(exc)
	not _reraise_value(line)
	ri := count(m[0][1])
	d := _enclosing_def(lines, i, ri)
	doc := _docstring(lines, d)
	_sectioned(doc)
	not _documents_errors(doc, exc)
	not _earlier_raise(lines, d, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function raises %s but its docstring, which documents arguments and returns, has no Raises section", [m[0][2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Only the first reported raise in a function.
_earlier_raise(lines, d, i) if {
	some k in helpers.span(d + 1, i - 1)
	m := regex.find_all_string_submatch_n(_raise_re, lines[k], 1)
	count(m) > 0
	not _exempt_exc(m[0][3])
	not _reraise_value(lines[k])
	_enclosing_def(lines, k, count(m[0][1])) == d
}
