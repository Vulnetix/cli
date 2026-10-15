# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1064

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1064",
	"name": "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
	"description": "Java: a method or constructor declaration (package-private constructors included) with more than seven parameters (the CISQ maintainability threshold). The declaration is read across line breaks, with annotations, string literals and generic type arguments removed before parameters are counted, so `Map<String, Integer> m` is one parameter. Such signatures are hard to call correctly (adjacent parameters of the same type are easily swapped) and usually mean a parameter object or builder is missing. Not reported: @Override methods, whose signature is imposed by the supertype or framework callback they implement (the supertype's own declaration is reported when it is scanned), @ParameterizedTest methods, whose parameters are the columns of their data source, calls and constructor invocations with many arguments, declarations of seven or fewer parameters, record headers (their components are fields), varargs counted as one parameter, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1064/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1064],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-params", "maintainability", "java", "cwe-1064"],
}

_max_params := 7

_mods := `(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\s+)*`

_method_re := concat("", [`^\s*`, _mods, `(?:<[^()]*>\s+)?([\w.$]+(?:<[^()]*>)?(?:\[\])*)\s+([A-Za-z_$][\w$]*)\s*\(`])

_ctor_re := `^\s*(?:public|protected|private)\s+([A-Z][\w$]*)\s*\(`

_not_types := {"return", "new", "throw", "else", "case", "yield", "assert", "package", "import", "record", "class", "interface", "enum", "await"}

_keywords := {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "try"}

_clean(line) := regex.replace(
	regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, ""),
	`@[\w.]+(?:\s*\([^()]*\))?`, "",
)

_degeneric(t) := regex.replace(regex.replace(regex.replace(t, `<[^<>]*>`, ""), `<[^<>]*>`, ""), `<[^<>]*>`, "")

_is_decl_head(s, _) if {
	m := regex.find_all_string_submatch_n(_method_re, s, 1)
	count(m) > 0
	not _not_types[m[0][1]]
	not _keywords[m[0][2]]
}

_is_decl_head(s, _) if regex.match(_ctor_re, s)

# A package-private constructor: `Shipment(` naming a class this file declares.
_is_decl_head(s, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Z][\w$]*)\s*\(`, s, 1)
	count(m) > 0
	regex.match(concat("", [`\b(?:class|enum)\s+`, m[0][1], `\b`]), content)
}

# The signature is imposed from elsewhere: an @Override of a supertype or
# framework method, or a @ParameterizedTest whose parameters are the columns
# of its data source. Looked for in the annotation lines just above.
_imposed(lines, i) if regex.match(`@(?:Override|ParameterizedTest)\b`, lines[i])

_imposed(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`^\s*@(?:Override|ParameterizedTest)\b`, lines[k])
	not _member_end_between(lines, k, i)
}

_member_end_between(lines, k, i) if {
	some m in numbers.range(k, i - 1)
	regex.match(`[;{}]\s*$`, _clean(lines[m]))
}

# The parameter list of the declaration starting at line i, if it is closed
# by `{`, `throws`, `;` or `default` within 15 lines.
_params(lines, i) := p if {
	j := min([count(lines), i + 15])
	txt := _degeneric(concat(" ", [_clean(l) | some l in array.slice(lines, i, j)]))
	m := regex.find_all_string_submatch_n(`^[^(]*\(([^()]*)\)\s*(?:\{|throws\b|;|default\b)`, txt, 1)
	count(m) > 0
	p := trim_space(m[0][1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, ",")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	s := _clean(line)
	_is_decl_head(s, content)
	p := _params(lines, i)
	p != ""
	n := count(split(p, ","))
	n > _max_params
	not _imposed(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Declaration takes %d parameters (more than %d): group related parameters into a parameter object or builder", [n, _max_params]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
