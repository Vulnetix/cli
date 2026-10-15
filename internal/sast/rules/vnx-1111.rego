# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1111

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1111",
	"name": "Incomplete I/O Documentation",
	"description": "A Python function whose docstring documents its inputs in a structured section (Google-style 'Args:'/'Parameters:' entries, including one entry naming several parameters such as 'x, y: the point', or Sphinx ':param name:') but leaves out one or more of the function's own parameters, so the documented interface is incomplete. Reported at the 'def' line, naming the missing parameters. Not reported: functions without a structured parameter section (an undocumented function is a different question), 'self'/'cls' (and a metaclass's 'mcs'/'mcls'/'metacls'), '*args'/'**kwargs', parameters whose name starts with an underscore, NumPy-style 'Parameters' sections with dashed underlines (not parsed), and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1111/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1111],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-io-docs", "docstring", "cwe-1111"],
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*(?:(?:Args|Arguments|Parameters|Params|Keyword Args|Keyword Arguments):\s*$|:(?:param|parameter|arg|argument|key|keyword)\s)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "def ")
	fn := _function(lines, i)
	documented := {d.name | some d in fn.documented}
	count(documented) > 0
	missing := {p.name |
		some p in fn.params
		p.stars == ""
		not p.name in {"self", "cls", "mcs", "mcls", "metacls"}
		not startswith(p.name, "_")
		not p.name in documented
	}
	count(missing) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Docstring documents the parameters of %s but omits %s; document every input so callers know what it accepts", [fn.name, concat(", ", sort([m | some m in missing]))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Docstring/signature parser (shared shape with VNX-1116) ───────────────

_def_re := `^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# the line that closes the signature: parentheses balanced and ending with ':'
_sig_end(lines, i) := k if {
	end := min([count(lines) - 1, i + 25])
	ks := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(?:#.*)?$`, lines[k])
		s := concat("\n", array.slice(lines, i, k + 1))
		count(indexof_n(s, "(")) == count(indexof_n(s, ")"))
	]
	count(ks) > 0
	k := ks[0]
}

_strip(s) := t if {
	a := regex.replace(s, `"[^"\n]*"|'[^'\n]*'`, "S")
	b := regex.replace(a, `\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}`, "B")
	c := regex.replace(b, `\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}`, "B")
	t := regex.replace(c, `\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}`, "B")
}

_params(sig) := ps if {
	m := regex.find_all_string_submatch_n(`(?s)def\s+[A-Za-z_]\w*\s*\((.*)\)\s*(?:->.*)?:\s*(?:#[^\n]*)?$`, sig, 1)
	count(m) > 0
	inner := _strip(m[0][1])
	ps := [p |
		some piece in split(inner, ",")
		pm := regex.find_all_string_submatch_n(`^\s*(\*{0,2})\s*([A-Za-z_]\w*)`, piece, 1)
		count(pm) > 0
		p := {"stars": pm[0][1], "name": pm[0][2]}
	]
}

_doc_start(lines, k) := d if {
	end := min([count(lines) - 1, k + 3])
	ds := [d | some d in numbers.range(k + 1, end); d > k; trim_space(lines[d]) != ""]
	count(ds) > 0
	d := ds[0]
	regex.match(`^\s*[rRuUbB]?("""|''')`, lines[d])
}

_doc_end(lines, d) := e if {
	q := regex.find_n(`"""|'''`, lines[d], 1)[0]
	count(indexof_n(lines[d], q)) == 1
	end := min([count(lines) - 1, d + 150])
	es := [e | some e in numbers.range(d + 1, end); e > d; contains(lines[e], q)]
	count(es) > 0
	e := es[0]
}

_function(lines, i) := fn if {
	m := regex.find_all_string_submatch_n(_def_re, lines[i], 1)
	count(m) > 0
	k := _sig_end(lines, i)
	ps := _params(concat("\n", array.slice(lines, i, k + 1)))
	d := _doc_start(lines, k)
	e := _doc_end(lines, d)
	fn := {"name": m[0][2], "params": ps, "documented": _documented(lines, d, e)}
}

_section_re := `^([ \t]*)(?:Args|Arguments|Parameters|Params|Keyword Args|Keyword Arguments|Kwargs|Other Parameters):\s*$`

_sphinx_re := `^\s*:(?:param|parameter|arg|argument|key|keyword)\s+(?:[^:\n]*\s)?(\*{0,2})([A-Za-z_]\w*)\s*:`

_item_re := `^\s*(\*{0,2})([A-Za-z_]\w*(?:\s*,\s*\*{0,2}[A-Za-z_]\w*)*)\s*(?:\([^)]*\))?\s*:`

_documented(lines, d, e) := docs if {
	sphinx := {{"name": mm[0][2], "idx": j} |
		some j in numbers.range(d, e)
		contains(lines[j], ":")
		mm := regex.find_all_string_submatch_n(_sphinx_re, lines[j], 1)
		count(mm) > 0
	}
	google := {{"name": trim(nm, " *"), "idx": j} |
		some h in numbers.range(d, e)
		regex.match(_section_re, lines[h])
		hi := _indent(lines[h])
		body := [j | some j in numbers.range(h + 1, e); j > h; j < e; trim_space(lines[j]) != ""]
		count(body) > 0
		ii := _indent(lines[body[0]])
		ii > hi
		stops := [j | some j in body; _indent(lines[j]) <= hi]
		last := _first_or(stops, e)
		some j in body
		j < last
		_indent(lines[j]) == ii
		mm := regex.find_all_string_submatch_n(_item_re, lines[j], 1)
		count(mm) > 0
		some nm in split(mm[0][2], ",")
	}
	docs := sphinx | google
}

_first_or(xs, dflt) := xs[0] if count(xs) > 0

_first_or(xs, dflt) := dflt if count(xs) == 0
