# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_607

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-607",
	"name": "Public Static Final Field References Mutable Object",
	"description": "Reports a Java field declared public, static and final (in any modifier order) whose initializer is a mutable object: a new HashMap/LinkedHashMap/TreeMap/ConcurrentHashMap/Hashtable/Properties/EnumMap, HashSet/TreeSet/LinkedHashSet, ArrayList/LinkedList/Vector/ArrayDeque/CopyOnWriteArrayList, Date, Calendar, SimpleDateFormat/DecimalFormat, StringBuilder/StringBuffer or BitSet, Arrays.asList(...), EnumSet.of/noneOf/allOf or Guava Lists/Maps/Sets.newXxx(...) (including an initializer on the line after the '='); also an UPPER_CASE constant of a file that declares only an interface, whose fields are implicitly public static final. final only fixes the reference: any code can still change the shared contents. Not reported: initializers wrapped in Collections.unmodifiable*, List.of/Set.of/Map.of, Guava Immutable*, Collections.empty*, a field assigned later in a static block, ThreadLocal holders, interface constants in a file that also declares a class or enum, private, protected or package-private fields, instance fields, strings, boxed numbers and plain Objects, arrays (VNX-582 covers public static final arrays), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-607/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [607],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["public-static-final-mutable", "cwe-607"],
}

_decl := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|static|final|transient|volatile)\s+)+)[A-Za-z_][\w.]*(?:\s*<[^=;]*>)?\s+[A-Za-z_]\w*\s*=\s*(.*)$`

_mutable := `^\s*(?:new\s+(?:java\.util\.(?:concurrent\.)?)?(?:HashMap|LinkedHashMap|TreeMap|ConcurrentHashMap|ConcurrentSkipListMap|WeakHashMap|IdentityHashMap|EnumMap|Hashtable|Properties|HashSet|LinkedHashSet|TreeSet|ConcurrentSkipListSet|ArrayList|LinkedList|Vector|Stack|ArrayDeque|PriorityQueue|CopyOnWriteArrayList|CopyOnWriteArraySet|Date|StringBuilder|StringBuffer|BitSet)\s*[<(]|new\s+(?:java\.text\.)?(?:SimpleDateFormat|DecimalFormat)\s*\(|new\s+(?:java\.util\.)?GregorianCalendar\s*\(|(?:java\.util\.)?Calendar\.getInstance\s*\(|(?:java\.util\.)?Arrays\.asList\s*\(|EnumSet\.(?:of|noneOf|allOf|range|copyOf)\s*\(|(?:com\.google\.common\.collect\.)?(?:Lists|Maps|Sets)\.new\w+\s*[<(])`

# A field of an interface is implicitly public static final, so it needs no
# modifiers: TYPE NAME = ... at member level of a file that declares only an
# interface. Restricted to UPPER_CASE names so a local in a default method
# is not mistaken for a constant.
_iface_decl := `^\s*(?:(?:public|static|final)\s+)*[A-Za-z_][\w.]*(?:\s*<[^=;]*>)?\s+[A-Z][A-Z0-9_]*\s*=\s*(.*)$`

_init(lines, i, rest) := rest if trim_space(rest) != ""

_init(lines, i, rest) := lines[j] if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 2)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "static")
	regex.match(`(?m)^\s*(?:(?:public|static|final)\s+){3}`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "final")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl, line, 1)
	count(m) > 0
	mods := m[0][1]
	regex.match(`\bpublic\b`, mods)
	regex.match(`\bstatic\b`, mods)
	regex.match(`\bfinal\b`, mods)
	regex.match(_mutable, _init(lines, i, m[0][2]))
	finding := {
		"rule_id": metadata.id,
		"message": "public static final field holds a mutable object: final fixes the reference, not the contents. Wrap it (Collections.unmodifiable*, List.of/Map.of) or make it private",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Interface constants: implicitly public static final.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "interface")
	regex.match(`(?m)^\s*(?:public\s+)?interface\s+[A-Z]\w*`, content)
	not regex.match(`(?m)^\s*(?:(?:public|private|protected|static|abstract|final|sealed)\s+)*(?:class|enum|record)\s+[A-Z]\w*`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_iface_decl, line, 1)
	count(m) > 0
	regex.match(_mutable, _init(lines, i, m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": "Interface constant holds a mutable object: interface fields are implicitly public static final, which fixes the reference, not the contents. Use List.of/Map.of or Collections.unmodifiable*",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
