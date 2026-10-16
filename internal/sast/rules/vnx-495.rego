# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_495

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-495",
	"name": "Private Data Structure Returned From A Public Method",
	"description": "A public Java method that returns an array type returns a private array field itself (return field; or return this.field;), so the caller receives a reference to the object's internal state and can change its elements. final on the field does not help: it fixes the reference, not the contents. Reported at the return statement. Not reported: a defensive copy (field.clone(), Arrays.copyOf, System.arraycopy into a new array, List.of/unmodifiableList), a private field initialised to an empty array (new T[0], {}), which cannot be changed, a local variable or method parameter that shadows the field, non-public methods, public fields (VNX-493 judges those), collections, and the pattern in comments or string literals. VNX-375, the general mutable-return rule, leaves these lines to this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-495/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [495],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["private-array", "defensive-copy", "encapsulation", "cwe-495"],
}

# private T[] name, private T name[], private T[][] name ...
_array_field_re := `^\s*private\s+(?:(?:static|final|transient|volatile)\s+)*[A-Za-z_][\w.]*(?:<[^;=()]*>)?\s*(?:(?:\[\]\s*)+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*(?:\[\]\s*)+)\s*(=[^;]*)?;`

_return_re := `^\s*return\s+(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*;`

# A method declaration start: modifiers, no trailing semicolon.
_method_start_re := `^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)+[^;=]*$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_name(m) := m[1] if m[1] != ""

_name(m) := m[2] if m[1] == ""

_empty_init(init) if regex.match(`=\s*(?:new\s+[\w.]+\s*(?:\[\s*0\s*\])+|\{\s*\})`, init)

# The nearest method declaration above the return, within 40 lines and at a
# smaller indent; its text joined with the next line for a split signature.
_enclosing_sig(lines, i) := sig if {
	ii := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		k < i
		_indent(lines[k]) < ii
		regex.match(_method_start_re, lines[k])
		not helpers.is_comment_line(lines[k])
	]
	count(ks) > 0
	k := ks[count(ks) - 1]
	sig := concat(" ", [lines[k], lines[min([k + 1, i])]])
}

_public_array_method(sig) if {
	regex.match(`^\s*(?:\w+\s+)*public\b`, sig)
	regex.match(`\[\]\s*[A-Za-z_]\w*\s*\(`, sig)
}

# A local of the same name is declared between the signature and the return.
_shadowed(lines, i, name) if {
	re := concat("", [`^\s*(?:final\s+)?[\w.<>]+\s*(?:\[\]\s*)*\s+`, name, `\s*(?:\[\]\s*)*=`])
	some k in numbers.range(max([0, i - 40]), i - 1)
	regex.match(re, lines[k])
	not startswith(trim_space(lines[k]), "private")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "private")
	contains(content, "[]")
	lines := split(content, "\n")
	fields := {name |
		some l in lines
		contains(l, "[]")
		startswith(trim_space(l), "private")
		m := regex.find_all_string_submatch_n(_array_field_re, l, 1)
		count(m) > 0
		not _empty_init(m[0][3])
		name := _name(m[0])
	}
	count(fields) > 0
	some i, line in lines
	contains(line, "return")
	not helpers.is_comment_line(line)
	r := _returned(line)
	fields[r]
	sig := _sig_for(lines, i, line)
	_public_array_method(sig)
	not _shadowed(lines, i, r)
	not _param_named(sig, r)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public method returns the private array '%s' itself; callers can modify the object's internal state. Return a copy (%s.clone()) or an unmodifiable view", [r, r]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A method parameter of the same name shadows the field.
_param_named(sig, name) if regex.match(concat("", [`[\w>\]]\s+`, name, `\s*(?:\[\]\s*)*[,)]`]), sig)

# The returned name, from a return statement on its own line or inline after
# a method's opening brace ({ return roles; }).
_returned(line) := r if {
	m := regex.find_all_string_submatch_n(_return_re, line, 1)
	count(m) > 0
	r := m[0][1]
}

_returned(line) := r if {
	not regex.match(_return_re, line)
	m := regex.find_all_string_submatch_n(`\{\s*return\s+(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*;\s*\}`, line, 1)
	count(m) > 0
	r := m[0][1]
}

_sig_for(_, _, line) := line if regex.match(`\)\s*(?:throws[^{]*)?\{\s*return\b`, line)

_sig_for(lines, i, line) := _enclosing_sig(lines, i) if not regex.match(`\)\s*(?:throws[^{]*)?\{\s*return\b`, line)
