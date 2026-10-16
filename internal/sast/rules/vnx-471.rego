# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_471

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-471",
	"name": "Modification of Assumed-Immutable Data (MAID)",
	"description": "A Java `public static final` field (modifiers in any order) whose value is mutable, so `final` freezes only the reference and any code in the process can change data the rest of the program treats as a constant: a new mutable collection or holder (ArrayList, LinkedList, HashMap, TreeMap, LinkedHashMap, HashSet, TreeSet, Vector, Hashtable, Properties, ArrayDeque, ConcurrentHashMap, Date, Calendar, StringBuilder, StringBuffer), or Arrays.asList(...), whose elements stay settable; an initialiser on the following line is read too. Not reported: immutable values (List.of, Set.of, Map.of, copyOf, Collections.unmodifiable*/empty*, Guava Immutable*, strings and primitives), arrays of any kind (a public static final array, `String[] TRUSTED_HOSTS = {...}`, is reported by VNX-582), private, package-private or instance fields, fields assigned later in a static block (whose value the line does not show), methods returning arrays, test sources, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-471/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [471],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["assumed-immutable", "mutable-constant", "cwe-471"],
}

_decl_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:public|static|final|transient|volatile)\s+)+)([\w.$]+(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_$][\w$]*)\s*((?:\[\s*\])*)\s*=\s*(.*)$`

_mutable_types := {
	"List", "ArrayList", "LinkedList", "Collection", "Map", "HashMap", "TreeMap", "LinkedHashMap",
	"SortedMap", "NavigableMap", "Set", "HashSet", "TreeSet", "LinkedHashSet", "SortedSet", "Vector",
	"Hashtable", "Properties", "Stack", "Deque", "Queue", "ArrayDeque", "ConcurrentHashMap",
	"ConcurrentMap", "Date", "Calendar", "StringBuilder", "StringBuffer",
}

_mutable_new := `^(?:new\s+(?:java\.util\.(?:concurrent\.)?)?(?:ArrayList|LinkedList|HashMap|TreeMap|LinkedHashMap|HashSet|TreeSet|LinkedHashSet|Vector|Hashtable|Properties|Stack|ArrayDeque|ConcurrentHashMap|Date|GregorianCalendar|StringBuilder|StringBuffer)\b|(?:java\.util\.)?Arrays\s*\.\s*asList\s*\(|Calendar\s*\.\s*getInstance\s*\()`

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, ""), `/\*.*?\*/`, "")

_mods_ok(mods) if {
	regex.match(`\bpublic\b`, mods)
	regex.match(`\bstatic\b`, mods)
	regex.match(`\bfinal\b`, mods)
}

# The initialiser, continued from the next line when this one ends at `=`.
_rhs(lines, i, r) := trim_space(_code(lines[i + 1])) if {
	trim_space(r) == ""
	i + 1 < count(lines)
}

_rhs(_, _, r) := trim_space(r) if trim_space(r) != ""

# Arrays are not judged here: a public static final array is VNX-582's
# finding (CWE-582), the array-specific form of this weakness.
_mutable(typ, dims, rhs) if {
	not regex.match(`\[`, concat("", [typ, dims]))
	base := regex.replace(regex.replace(typ, `\s*<.*$`, ""), `^.*\.`, "")
	_mutable_types[base]
	regex.match(_mutable_new, rhs)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "final")
	regex.match(`(?m)^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|static|final)\s+){3}`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "static")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl_re, _code(line), 1)
	count(m) > 0
	_mods_ok(m[0][1])
	rhs := _rhs(lines, i, m[0][5])
	_mutable(m[0][2], m[0][4], rhs)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("public static final field %s holds a mutable value: final freezes only the reference, so any code can change what the program treats as a constant. Use List.of/Set.of/Map.of, an unmodifiable wrapper, or return a copy", [m[0][3]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
