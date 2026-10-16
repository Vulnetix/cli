# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_584

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-584",
	"name": "Return Inside Finally Block",
	"description": "A return statement inside a finally block (Java, JavaScript/TypeScript and Python), at any nesting depth within the block, including the one-line form finally { return x; }, a guarded return on one line (if (c) return x; else return y; in Java/JS, if c: return x in Python) and a return in a Java switch rule (case X -> { return 0; }). A return in finally silently discards any exception thrown in the try or catch block and overrides the try block's own return value. The finally block is bounded by brace depth (indentation for Python) within 80 lines. Not reported: a return in a lambda, arrow function, anonymous class or nested def/function opened inside the finally block, a return after the block closes, a return in the try or catch block, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-584/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [584],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["return-in-finally", "cwe-584"],
}

_brace_ext := {".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}

_brace_lang(path) if {
	some ext in _brace_ext
	endswith(path, ext)
}

_message := "return inside a finally block discards any exception thrown by the try or catch block and overrides its return value. Move the return out of the finally block"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Brace languages ──────────────────────────────────────────────────────

# The line with string literals blanked and a trailing // comment removed,
# so braces and keywords inside them do not count.
_code(line) := c if {
	s := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`", `""`)
	c := regex.replace(s, `//.*$`, "")
}

_net(s) := strings.count(s, "{") - strings.count(s, "}")

# A function body opened on this line: lambda, arrow, function, anonymous
# class or a method declaration.
_fn_open_re := `->\s*\{|=>|\bfunction\b|\bnew\s+[\w.<>]+\s*\([^)]*\)\s*\{|^\s*(?:@\w+\s+)*(?:(?:public|private|protected|static|final|synchronized|async)\s+)*[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{`

# Relative brace depth after line j, counting from the `finally` keyword.
_depth(codes, i, tailnet, j) := tailnet + sum([_net(codes[k]) | some k in numbers.range(i + 1, j)]) if j > i

_depth(_, i, tailnet, i) := tailnet

findings contains finding if {
	some path, content in input.file_contents
	_brace_lang(path)
	contains(content, "finally")
	regex.match(`\bfinally\s*(?:\{|$|\r)`, content)
	contains(content, "return")
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	contains(line, "finally")
	not helpers.is_comment_line(line)
	ci := _code(line)
	parts := regex.split(`\bfinally\b`, ci)
	count(parts) > 1
	tail := parts[count(parts) - 1]
	regex.match(`^\s*(?:\{|$|\r)`, tail)
	hi := min([n - 1, i + 80])
	codes := {k: _code(lines[k]) | some k in numbers.range(i + 1, hi)}
	o := _open_line(codes, i, tail, hi)
	tailnet := _net(tail)
	some j in numbers.range(o, hi)
	_return_at(codes, i, tail, j)
	_in_block(codes, i, o, tailnet, j)
	not _in_nested_fn(codes, i, o, tail, tailnet, j)
	finding := _finding(path, j, lines[j])
}

# The line holding the finally block's opening brace.
_open_line(_, i, tail, _) := i if contains(tail, "{")

_open_line(codes, i, tail, hi) := o if {
	not contains(tail, "{")
	i + 1 <= hi
	cands := [k | some k in numbers.range(i + 1, min([hi, i + 2])); regex.match(`^\s*\{`, codes[k])]
	count(cands) > 0
	o := min(cands)
}

_text(_, i, tail, i) := tail

_text(codes, i, _, j) := codes[j] if j > i

_return_at(codes, i, tail, j) if {
	t := _text(codes, i, tail, j)
	contains(t, "return")
	regex.match(`(?:^\s*|[{;)]\s*|\belse\s+)return\b`, t)
}

# No line from the opening brace up to (not including) j brings the depth
# back to zero, so j is still inside the block.
_in_block(codes, i, o, tailnet, j) if {
	_depth(codes, i, tailnet, o) > 0
	not _closed_before(codes, i, o, tailnet, j)
}

# Inline `finally { return x; }`: the block opens and closes on line i.
_in_block(_, i, i, tailnet, i) if tailnet <= 0

_closed_before(codes, i, o, tailnet, j) if {
	o <= j - 1
	some k in numbers.range(o, j - 1)
	_depth(codes, i, tailnet, k) <= 0
}

# A function literal opened on line k between the block's opening and j,
# still open at j.
_in_nested_fn(codes, i, o, tail, tailnet, j) if {
	some k in numbers.range(o, j - 1)
	regex.match(_fn_open_re, _text(codes, i, tail, k))
	not _switch_rule(_text(codes, i, tail, k))
	_depth(codes, i, tailnet, j - 1) > _depth(codes, i, tailnet, k - 1)
}

# The return sits after a function opener on its own line.
_in_nested_fn(codes, i, _, tail, _, j) if {
	t := _text(codes, i, tail, j)
	regex.match(concat("", ["(?:", _fn_open_re, `).*\breturn\b`]), t)
	not _switch_rule(t)
}

# ── Python ───────────────────────────────────────────────────────────────

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_or_comment(line) if trim_space(line) == ""

_blank_or_comment(line) if startswith(trim_space(line), "#")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "finally")
	regex.match(`(?m)^\s*finally\s*:`, content)
	lines := split(content, "\n")
	n := count(lines)
	some i, line in lines
	regex.match(`^\s*finally\s*:`, line)
	fi := _indent(line)
	hi := min([n - 1, i + 80])
	some j in numbers.range(i, hi)
	_py_return(lines, i, j)
	not _py_closed(lines, i, fi, j)
	not _py_nested_def(lines, i, j)
	finding := _finding(path, j, lines[j])
}

_py_return(lines, i, i) if regex.match(`^\s*finally\s*:\s*return\b`, lines[i])

_py_return(lines, i, j) if {
	j > i
	regex.match(`^\s*(?:(?:if|elif|else|for|while|with)\b[^#]*:\s*)?return\b`, lines[j])
	_indent(lines[j]) > _indent(lines[i])
}

# A code line between the finally and j at the finally's indent or less ends
# the block.
_py_closed(lines, i, fi, j) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	not _blank_or_comment(lines[k])
	_indent(lines[k]) <= fi
}

# A def or class inside the block encloses j.
_py_nested_def(lines, i, j) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`^\s*(?:async\s+def|def|class)\b`, lines[k])
	ik := _indent(lines[k])
	_indent(lines[j]) > ik
	not _py_closed(lines, k, ik, j)
}

# A Java switch rule `case X -> {` / `default -> {` opens a block of the
# enclosing method, not a lambda: a return in it leaves the finally block.
_switch_rule(t) if regex.match(`^\s*(?:case\b[^>]*|default\s*)->\s*\{`, t)
