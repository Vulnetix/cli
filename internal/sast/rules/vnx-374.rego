# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_374

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-374",
	"name": "Passing Mutable Objects to an Untrusted Method",
	"description": "A public or protected Java method or constructor stores a mutable object it was passed straight into a field, so the caller keeps a live reference to the object's internal state and can change it after any validation the object did (the object and its untrusted caller share one mutable value). Reported: `this.field = param;` (or `field = param;` for a field declared in the file) inside a public or protected method or constructor whose parameter `param` is an array or a mutable collection or date type (List, ArrayList, LinkedList, Map, HashMap, TreeMap, LinkedHashMap, Set, HashSet, TreeSet, LinkedHashSet, Collection, Deque, Queue, Date, Calendar, StringBuilder), or varargs (byte... p), including a signature that spans lines and a one-line setter or fluent builder (`public void setX(List<T> x) { this.x = x; }`, `{ this.x = x; return this; }`). Not reported: a defensive copy or view (new ArrayList<>(p), List.copyOf(p), p.clone(), Arrays.copyOf(p, ...), new Date(p.getTime()), Collections.unmodifiable*), immutable parameter types (String, primitives, ImmutableList), private and package-private methods, a value derived from the parameter rather than the parameter itself, JPA/document entity and JAXB-bound classes (@Entity, @Embeddable, @MappedSuperclass, @Document, @XmlRootElement, @XmlType), whose setters a framework drives, test sources and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-374/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [374],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["passing-mutable-objects", "cwe-374"],
}

_mutable_types := `(?:java\.util\.)?(?:List|ArrayList|LinkedList|Map|HashMap|TreeMap|LinkedHashMap|Set|HashSet|TreeSet|LinkedHashSet|Collection|Deque|ArrayDeque|Queue|Date|Calendar|GregorianCalendar|StringBuilder)`

_entity_re := `(?m)^\s*@(?:Entity|Embeddable|MappedSuperclass|Document|XmlRootElement|XmlType|javax\.persistence\.Entity|jakarta\.persistence\.Entity)\b`

# `this.f = p;` or `f = p;`
_assign_re := `^\s*(this\s*\.\s*)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;\s*(?://.*)?$`

# A method or constructor declaration (its parameter list may continue on the
# next lines).
_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(public|protected|private)\s+)?(?:static\s+|final\s+|synchronized\s+)*(?:<[^>]*>\s+)?(?:[A-Za-z_][\w.<>\[\], ?]*\s+)?[A-Za-z_]\w*\s*\([^;]*$`

_is_decl(line) if {
	regex.match(_decl_re, line)
	not regex.match(`^\s*(?:return|new|throw|else|if|for|while|switch|catch|try|do|synchronized\s*\()\b`, line)
	not regex.match(`=`, regex.replace(line, `\([^)]*$`, ""))
}

_decl_start(lines, i) := s if {
	cands := [k |
		some k in numbers.range(max([0, i - 12]), i - 1)
		_is_decl(lines[k])
	]
	count(cands) > 0
	s := max(cands)
}

# The parameter list, from the declaration line to the line that opens the body.
_params(lines, s, i) := p if {
	ends := [k | some k in numbers.range(s, i - 1); contains(lines[k], "{")]
	count(ends) > 0
	p := concat(" ", array.slice(lines, s, ends[0] + 1))
}

_mutable_param(params, p) if regex.match(concat("", [`[(,]\s*(?:final\s+)?(?:@\w+\s+)*`, _mutable_types, `(?:\s*<[^()]*?>)?\s+`, p, `\s*[,)]`]), params)

_mutable_param(params, p) if regex.match(concat("", [`[(,]\s*(?:final\s+)?(?:@\w+\s+)*[A-Za-z_][\w.]*(?:\s*<[^()]*?>)?\s*(?:\[\s*\])+\s+`, p, `\s*[,)]`]), params)

_mutable_param(params, p) if regex.match(concat("", [`[(,]\s*(?:final\s+)?(?:@\w+\s+)*[A-Za-z_][\w.]*\s+`, p, `\s*\[\s*\]\s*[,)]`]), params)

# Varargs: `byte... data` is an array.
_mutable_param(params, p) if regex.match(concat("", [`[(,]\s*(?:final\s+)?(?:@\w+\s+)*[A-Za-z_][\w.]*(?:\s*<[^()]*?>)?\s*\.\.\.\s*`, p, `\s*[,)]`]), params)

_declared_field(content, f) if regex.match(concat("", [`(?m)^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:private|protected|public)\s+[^=;(]*\b`, f, `\s*[=;]`]), content)

# `x = x;` without `this.` assigns the parameter to itself, not to a field.
_distinct(this, _, _) if this != ""

_distinct("", f, p) if f != p

_field_target(_, this, _) if this != ""

_field_target(content, "", f) if _declared_field(content, f)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(concat("", [`\b`, _mutable_types, `\b|\[\s*\]|\.\.\.`]), content)
	not helpers.is_test_path(path)
	not regex.match(_entity_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	f := m[0][2]
	p := m[0][3]
	_distinct(m[0][1], f, p)
	not helpers.is_comment_line(line)
	_field_target(content, m[0][1], f)
	s := _decl_start(lines, i)
	regex.find_all_string_submatch_n(_decl_re, lines[s], 1)[0][1] in {"public", "protected"}
	params := _params(lines, s, i)
	_mutable_param(params, p)
	finding := _finding(path, i, line, f, p)
}

# A one-line setter or constructor: `public void setX(List<T> x) { this.x = x; }`.
_one_line_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:public|protected)\s+[^=;{(]*\(([^)]*)\)\s*(?:throws\s[^{]*)?\{\s*(this\s*\.\s*)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;\s*(?:return\s+this\s*;\s*)?\}`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)\{\s*(?:this\s*\.\s*)?\w+\s*=\s*\w+\s*;\s*(?:return\s+this\s*;\s*)?\}`, content)
	not helpers.is_test_path(path)
	not regex.match(_entity_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	m := regex.find_all_string_submatch_n(_one_line_re, line, 1)
	count(m) > 0
	f := m[0][3]
	p := m[0][4]
	_distinct(m[0][2], f, p)
	_field_target(content, m[0][2], f)
	_mutable_param(concat("", ["(", m[0][1], ")"]), p)
	finding := _finding(path, i, line, f, p)
}

_finding(path, i, line, f, p) := {
	"rule_id": metadata.id,
	"message": sprintf("Mutable argument '%s' is stored directly in field '%s', so the caller can still change this object's state: store a copy (new ArrayList<>(...), List.copyOf, clone())", [p, f]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
