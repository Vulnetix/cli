# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_375

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-375",
	"name": "Returning a Mutable Object to an Untrusted Caller",
	"description": "A public or protected Java method returns a reference to one of the object's own mutable fields, so any caller can change the object's internal state without going through its methods (an exposed internal representation). Reported: `return field;` or `return this.field;` in a public or protected method (also a one-line getter) where the field is declared in the same file as an array or as a mutable collection or date type (List, ArrayList, LinkedList, Map, HashMap, TreeMap, LinkedHashMap, Set, HashSet, TreeSet, LinkedHashSet, Collection, Deque, Queue, Date, Calendar, StringBuilder). Not reported: a returned copy or view (Collections.unmodifiableList, List.copyOf, new ArrayList<>(x), clone(), new Date(d.getTime())), fields initialised with an immutable value (List.of, Set.of, Map.of, Collections.unmodifiable*, Collections.empty*, Immutable*, copyOf), immutable field types (String, primitives, ImmutableList), package-private and private methods, a local variable that shadows the field, JPA/document entity classes (@Entity, @Embeddable, @MappedSuperclass, @Document) and JAXB-bound classes (@XmlRootElement, @XmlType), whose collection getters the framework requires to be live, test sources, comments and the pattern inside a string literal.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-375/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [375],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["returning-mutable-objects", "cwe-375"],
}

_mutable_type := `(?:java\.util\.)?(?:List|ArrayList|LinkedList|Map|HashMap|TreeMap|LinkedHashMap|Set|HashSet|TreeSet|LinkedHashSet|Collection|Deque|ArrayDeque|Queue|Date|Calendar|GregorianCalendar|StringBuilder)(?:\s*<[^;=]*>)?|[A-Za-z_][\w.]*(?:\s*<[^;=]*>)?\s*(?:\[\s*\])+`

_field_re := concat("", [`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:private|protected|public)\s+(?:static\s+|final\s+|transient\s+|volatile\s+)*(?:`, _mutable_type, `)\s+([A-Za-z_]\w*)\s*(=\s*[^;]*)?;`])

_immutable_init_re := `\b(?:List|Set|Map)\s*\.\s*(?:of|copyOf)\s*\(|Collections\s*\.\s*(?:unmodifiable|empty)|\bImmutable\w*|\bcopyOf\s*\(`

_entity_re := `(?m)^\s*@(?:Entity|Embeddable|MappedSuperclass|Document|XmlRootElement|XmlType|javax\.persistence\.Entity|jakarta\.persistence\.Entity)\b`

_mutable_fields(lines) := {name |
	some l in lines
	regex.match(`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:private|protected|public)\s`, l)
	m := regex.find_all_string_submatch_n(_field_re, l, 1)
	count(m) > 0
	name := m[0][1]
	not regex.match(_immutable_init_re, m[0][2])
}

_method_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(public|protected|private)\s+)?(?:static\s+|final\s+|synchronized\s+|abstract\s+)*(?:<[^>]*>\s+)?[A-Za-z_][\w.<>\[\], ?]*\s+[A-Za-z_]\w*\s*\([^;{]*(?:\{.*)?$`

_is_method_decl(line) if {
	regex.match(_method_re, line)
	not regex.match(`^\s*(?:return|new|throw|else|if|for|while|switch|catch)\b`, line)
}

_method_start(lines, i) := s if {
	cands := [k |
		some k in numbers.range(max([0, i - 8]), i)
		_is_method_decl(lines[k])
	]
	count(cands) > 0
	s := max(cands)
}

_visibility(line) := v if {
	m := regex.find_all_string_submatch_n(_method_re, line, 1)
	v := m[0][1]
}

_shadowed(lines, s, i, name) if {
	s + 1 <= i
	some k in numbers.range(s + 1, i)
	not regex.match(`^\s*return\b`, lines[k])
	regex.match(concat("", [`^\s*(?:final\s+)?[A-Za-z_][\w.<>\[\], ?]*\s+`, name, `\s*[=;]`]), lines[k])
}

# A parameter of the method with the same name.
_shadowed(lines, s, _, name) if regex.match(concat("", [`\(\s*[^)]*\b`, name, `\s*[,)]`]), lines[s])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "return")
	not helpers.is_test_path(path)
	not regex.match(_entity_re, content)
	lines := split(content, "\n")
	fields := _mutable_fields(lines)
	count(fields) > 0
	some i, line in lines
	contains(line, "return")
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	m := regex.find_all_string_submatch_n(`(?:^|[{;])\s*return\s+(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*;`, code, 1)
	count(m) > 0
	name := m[0][1]
	fields[name]
	s := _method_start(lines, i)
	_visibility(lines[s]) in {"public", "protected"}
	not _shadowed(lines, s, i, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Method returns the internal mutable field '%s', so callers can modify this object's state: return a copy or an unmodifiable view", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
