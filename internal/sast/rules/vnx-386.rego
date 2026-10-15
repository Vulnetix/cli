# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_386

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-386",
	"name": "Symbolic Name not Mapping to Correct Object",
	"description": "A Java class is looked up by a name assembled at run time, so the symbolic name can resolve to a class other than the one the code expects, including any class on the classpath an attacker can name. Reported: Class.forName() and ClassLoader.loadClass() whose class-name argument is built by concatenation or String.format/formatted with a variable part (BASE + kind, pkg + \".\" + name, PREFIX + kind.toLowerCase(), also across a line break), or is a variable assigned in the 15 lines above from such a concatenation or from request data (getParameter, getHeader, getQueryString, getPathInfo, getCookies, readLine). Not reported: literal class names, ALL_CAPS constants, X.class.getName(), concatenations of literals only or of literals and calls with no variable receiver (getClass().getPackage().getName() + \".Impl\"), a lookup preceded in the 10 lines above by an allow-list check of the variable (ALLOWED.contains(kind), a validator, a matches() pattern), map-based registries that return Class objects, comments and string literals. Request-supplied class names are also reported by VNX-470 (unsafe reflection).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-386/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [386],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["symbolic-name", "cwe-386"],
}

_unquote(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`)

_sink_re := `(?:\bClass\s*\.\s*forName|\.\s*loadClass)\s*\(((?:[^(),]|\((?:[^()]|\([^()]*\))*\))*)`

# Identifiers in an expression that are variables: not calls, not ALL_CAPS
# constants, not String/MessageFormat receivers.
_vars(expr) := {v |
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_]\w*)*)(\s*\()?`, expr, -1)
	m[2] == ""
	v := m[1]
	parts := split(regex.replace(v, `\s+`, ""), ".")
	last := parts[count(parts) - 1]
	not regex.match(`^[A-Z][A-Z0-9_]*$`, last)
	last != "class"
	not regex.match(`^(?:true|false|null|this|new)$`, v)
}

# The receiver of a method call is a variable too: `kind.toLowerCase()` is
# `kind`. A capitalised receiver (String.valueOf) is a class.
_receivers(expr) := {r |
	some m in regex.find_all_string_submatch_n(`([a-z_][\w]*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*[A-Za-z_]\w*\s*\(`, expr, -1)
	r := m[1]
	not regex.match(`^(?:this|super|new)$`, r)
}

_dynamic(arg) if {
	contains(arg, "+")
	count(_vars(arg) | _receivers(arg)) > 0
}

_dynamic(arg) if {
	regex.match(`\bformat(?:ted)?\s*\(`, arg)
	count(_vars(regex.replace(arg, `\b(?:String|MessageFormat)\s*\.\s*format\s*\(`, "("))) > 0
}

_source_re := `getParameter(?:Values)?\s*\(|getHeader\s*\(|getQueryString\s*\(|getPathInfo\s*\(|getCookies\s*\(|readLine\s*\(|getRequestURI\s*\(`

_dynamic_var(lines, i, v) if {
	regex.match(`^[A-Za-z_]\w*$`, v)
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	not helpers.is_comment_line(lines[j])
	m := regex.find_all_string_submatch_n(concat("", [`\b`, v, `\s*=\s*([^;]*)`]), _unquote(lines[j]), 1)
	count(m) > 0
	_tainted_rhs(m[0][1])
}

_tainted_rhs(rhs) if regex.match(_source_re, rhs)

_tainted_rhs(rhs) if _dynamic(rhs)

_guarded(lines, i, vs) if {
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	some v in vs
	regex.match(concat("", [`(?i)(?:allow|white|permit|valid|known|safe|trusted)\w*\s*(?:\.\s*\w+\s*)?\(\s*`, v, `\b|\b`, v, `\s*\.\s*matches\s*\(`]), lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)\bforName\s*\(|\.\s*loadClass\s*\(`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`forName|loadClass`, raw)
	not helpers.is_comment_line(raw)
	text := _unquote(concat(" ", array.slice(lines, i, min([count(lines), i + 2]))))
	m := regex.find_all_string_submatch_n(_sink_re, _unquote(raw), 1)
	count(m) > 0
	m2 := regex.find_all_string_submatch_n(_sink_re, text, 1)
	arg := trim_space(m2[0][1])
	_reportable(lines, i, arg)
	not _guarded(lines, i, _vars(arg) | _receivers(arg))
	finding := {
		"rule_id": metadata.id,
		"message": "Class is looked up by a name assembled at run time, which can resolve to an unexpected or attacker-chosen class: map the input to a fixed set of Class objects or check the name against an allow-list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

_reportable(_, _, arg) if _dynamic(arg)

_reportable(lines, i, arg) if _dynamic_var(lines, i, arg)
