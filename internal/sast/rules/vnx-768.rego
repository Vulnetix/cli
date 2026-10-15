# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_768

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-768",
	"name": "Incorrect Short Circuit Evaluation",
	"description": "Reports a Java or C# null guard joined to the rest of a condition by the non-short-circuit operator: `x != null & x.m()` (or `null != x & x[...]`) and `x == null | x.m()`, where the right operand dereferences the same variable. With `&` and `|` both operands are always evaluated, so the guard does not protect the dereference and a null value throws NullPointerException / NullReferenceException; `&&` and `||` were meant. A guard ending a line followed by its operand on the next line is also read. Not reported: `&&`, `||`, `&=` and `|=`, bitwise arithmetic on integers, null checks joined by `&` whose right operand does not dereference the guarded variable (no failure, only style), C# null-conditional access (`x?.y`), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-768/",
	"languages": ["java", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [768],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-short-circuit", "cwe-768"],
}

_ext(path) if endswith(path, ".java")

_ext(path) if endswith(path, ".cs")

# guard, then a single & (not && or &=), then the remainder of the line
_and_re := `(?:([A-Za-z_][\w.]*)\s*!=\s*null|\bnull\s*!=\s*([A-Za-z_][\w.]*))\s*\)?\s*&([^&=].*|)$`

_or_re := `(?:([A-Za-z_][\w.]*)\s*==\s*null|\bnull\s*==\s*([A-Za-z_][\w.]*))\s*\)?\s*\|([^|=].*|)$`

# Remove string literals so a guard written in a message is not code.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_guard(line) := m if {
	m := regex.find_all_string_submatch_n(_and_re, line, -1)
	count(m) > 0
}

_guard(line) := m if {
	m := regex.find_all_string_submatch_n(_or_re, line, -1)
	count(m) > 0
}

_rest(lines, i, r) := r if trim_space(r) != ""

_rest(lines, i, r) := lines[i + 1] if {
	trim_space(r) == ""
	i + 1 < count(lines)
}

_var(g) := g[1] if g[1] != ""

_var(g) := g[2] if g[1] == ""

_derefs(rest, v) if {
	re := concat("", [`(?:^|[^\w.?])`, replace(v, ".", `\.`), `\s*(?:\.|\[)`])
	regex.match(re, rest)
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	contains(content, "null")
	regex.match(`null\s*\)?\s*[&|]`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "null")
	not helpers.is_comment_line(raw)
	line := _code(raw)
	some g in _guard(line)
	v := _var(g)
	_derefs(_rest(lines, i, g[3]), v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Null check on '%s' is joined with a non-short-circuit operator, so the dereference on the right still runs when it is null; use && / ||", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}
