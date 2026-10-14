package vulnetix.rules.vnx_node_027

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-027",
	"name": "Assignment to innerHTML without sanitization",
	"description": "Reports an assignment (= or +=) to an element's innerHTML or outerHTML, in JavaScript/TypeScript files and inline scripts of HTML/template pages, whose value is not a constant: a variable, a property, a call, a concatenation with one, or a template literal with an interpolation (the value may continue on the next line). The browser parses that string as HTML, so a value carrying user, URL, message or server data runs script. Not reported: string, template or numeric literals, a ternary choosing between literals, a const assigned a literal, a value passed through DOMPurify.sanitize or an escape/encode/sanitize helper (inline or assigned a few lines above), comparisons (innerHTML === x), textContent/innerText, comments and strings, and third-party library copies (vendor/, libs/, node_modules/, dist/, jquery/bootstrap/angular files, minified files). Overlaps VNX-NODE-005 and VNX-NODE-012, which report every innerHTML sink.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-027/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "innerhtml", "dom"],
}

_exts := {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte", ".ejs", ".hbs", ".php", ".erb", ".jsp", ".cshtml"}

_in_scope(path) if {
	some e in _exts
	endswith(path, e)
}

_third_party(path) if regex.match(`(^|/)(vendors?|third[-_]?party|bower_components|node_modules|dist|libs|plugins)/`, path)

_third_party(path) if regex.match(`(?i)(^|/)[^/]*(jquery|bootstrap|angular|prototype|mootools|html5shiv|modernizr|three|wysihtml|ace)[^/]*\.js$`, path)

# a versioned library copy: name-1.2.3.js
_third_party(path) if regex.match(`(^|/)[A-Za-z][\w.-]*-v?\d+\.\d+(\.\d+)?\.js$`, path)

_third_party(path) if regex.match(`[.-]min\.js$|\.bundle\.js$`, path)

_sink_re := `\.(?:inner|outer)HTML\s*\+?=(?:[^=]|$)`

# Literal contents removed; an interpolating template keeps `${`.
_strip(s) := regex.replace(
	regex.replace(s, "`[^`$]*`", `''`),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`,
	`''`,
)

# The assigned expression: the rest of line i, continued on the next code
# line when the assignment ends the line.
_rhs(lines, i) := r if {
	parts := regex.split(`\.(?:inner|outer)HTML\s*\+?=`, lines[i])
	r0 := trim_space(parts[1])
	r0 != ""
	r := r0
}

_rhs(lines, i) := r if {
	parts := regex.split(`\.(?:inner|outer)HTML\s*\+?=`, lines[i])
	trim_space(parts[1]) == ""
	j := helpers.next_code_index(lines, i, 3)
	r := lines[j]
}

_sanitizer_re := `(?i)(sanitiz|purify|escape|encode|filterxss|xss\(|textcontent|innertext|createtextnode)`

_idents(code) := {m[0] |
	some m in regex.find_all_string_submatch_n(`[A-Za-z_$][\w$]*`, code, -1)
}

_constant_ident(content, id) if {
	regex.match(concat("", [`(?m)^\s*(?:export\s+)?const\s+`, id, `\s*=\s*(?:'[^'\n]*'|"[^"\n]*"|-?[0-9.]+)\s*;?\s*$`]), content)
}

_constant_ident(_, id) if id in {"true", "false", "null", "undefined"}

# a ternary that picks between literals
_literal_choice(code) if regex.match(`^[^?]*\?\s*''\s*:\s*''\s*;?\s*$`, code)

_sanitized_above(lines, i, id) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[j], id)
	regex.match(concat("", [`\b`, id, `\s*=[^=]`]), lines[j])
	regex.match(_sanitizer_re, lines[j])
}

_dynamic(content, lines, i, rhs) if {
	code := _strip(rhs)
	not regex.match(_sanitizer_re, rhs)
	not _literal_choice(code)
	_has_dynamic_part(content, lines, i, code)
}

_has_dynamic_part(_, _, _, code) if contains(code, "${")

_has_dynamic_part(content, lines, i, code) if {
	ids := _idents(code)
	count(ids) > 0
	dyn := {id | some id in ids; not _constant_ident(content, id)}
	count(dyn) > 0
	not _all_sanitized(lines, i, dyn)
}

_all_sanitized(lines, i, ids) if {
	every id in ids {
		_sanitized_above(lines, i, id)
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	contains(content, "HTML")
	regex.match(`\.(inner|outer)HTML\s*\+?=[^=]`, content)
	not _third_party(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "HTML")
	count(line) < 400
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip(line))
	rhs := _rhs(lines, i)
	_dynamic(content, lines, i, rhs)
	finding := {
		"rule_id": metadata.id,
		"message": "innerHTML/outerHTML assigned a non-constant value without sanitisation; use textContent, DOM construction, or DOMPurify.sanitize() before assigning HTML",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
