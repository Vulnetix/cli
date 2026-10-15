# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1097

import rego.v1

metadata := {
	"id": "VNX-1097",
	"name": "Persistent Storable Data Element without Associated Comparison Control Element",
	"description": "A class defines an ordering but not the equality that must agree with it, so the comparison controls it carries are incomplete: Java classes with compareTo() and no equals(Object), Kotlin classes with override fun compareTo() and no override fun equals(), and Python classes with __lt__/__le__/__gt__/__ge__ and no __eq__ (functools.total_ordering included, which documents that the class must supply __eq__). Sorted collections (TreeSet, TreeMap, bisect, sorted dedupe) then treat two objects as the same element while hash-based collections and == treat them as different, so lookups, de-duplication and stored copies disagree depending on which structure holds them. Reported: the compareTo line, or the first ordering method of a Python class. Not reported: classes that also define equality, Java records and enums, Lombok @Data/@Value/@EqualsAndHashCode classes, Kotlin data, enum and value classes, Python dataclasses/attrs classes, classes that extend another class (equality may be inherited), interfaces, and comments. The related pairing of equals() with hashCode() is VNX-581.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1097/",
	"languages": ["java", "kotlin", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1097],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["equality", "comparison", "reliability", "cwe-1097"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_is_comment(line) if startswith(trim_space(line), "//")

_is_comment(line) if startswith(trim_space(line), "*")

_is_comment(line) if startswith(trim_space(line), "/*")

_is_comment(line) if startswith(trim_space(line), "#")

# Nearest header above i with a smaller indent.
_enclosing(lines, headers, i) := k if {
	cands := [h | some h in headers; h < i; _indent(lines[h]) < _indent(lines[i])]
	count(cands) > 0
	k := max(cands)
}

# Brace-delimited body of the header at k: up to the first '}' at its indent.
_brace_end(lines, k) := e if {
	ik := _indent(lines[k])
	n := count(lines) - 1
	ends := [m | some m in numbers.range(k + 1, n); k + 1 <= n; _indent(lines[m]) <= ik; startswith(trim_space(lines[m]), "}")]
	e := min(array.concat([n], ends))
}

# Header text up to its opening brace (at most three lines).
_header_text(lines, k) := concat(" ", [lines[m] | some m in numbers.range(k, min([count(lines) - 1, k + 2]))])

_defines_in(lines, k, e, re) if {
	some m in numbers.range(k + 1, e)
	regex.match(re, lines[m])
	not _is_comment(lines[m])
}

# ---------------- Java ----------------

_java_header_re := `^\s*(?:(?:public|protected|private|abstract|static|final|sealed|non-sealed|strictfp)\s+)*(class|record|enum|interface)\s+\w+`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "compareTo")
	lines := split(content, "\n")
	headers := [h | some h, l in lines; regex.match(_java_header_re, l)]
	some i, line in lines
	regex.match(`^\s*(?:@\w+\s+)*(?:public\s+)?(?:final\s+)?int\s+compareTo\s*\(`, line)
	k := _enclosing(lines, headers, i)
	m := regex.find_all_string_submatch_n(_java_header_re, lines[k], 1)
	m[0][1] == "class"
	h := _strip_generics(split(_header_text(lines, k), "{")[0])
	not regex.match(`\bextends\b`, h)
	not _lombok_equals(lines, k)
	e := _brace_end(lines, k)
	not _defines_in(lines, k, e, `\bboolean\s+equals\s*\(\s*(?:final\s+)?(?:@\w+\s+)*(?:java\.lang\.)?Object\b`)
	finding := _finding(path, i, line, "compareTo() is defined without equals(Object); objects that compare as 0 are still unequal to equals() and HashSet, so sorted and hashed collections disagree. Define equals (and hashCode) consistently with compareTo")
}

# Lombok generates equals() for @Data, @Value and @EqualsAndHashCode; the
# annotation sits on the header line or in the few lines above it.
_lombok_equals(lines, k) if {
	some m in numbers.range(max([0, k - 4]), k)
	regex.match(`@(?:lombok\.)?(?:Data|Value|EqualsAndHashCode)\b`, lines[m])
}

# `class Range<T extends Comparable<T>>`: a bound is not a superclass.
_strip_generics(s) := regex.replace(regex.replace(regex.replace(s, `<[^<>]*>`, ""), `<[^<>]*>`, ""), `<[^<>]*>`, "")

# ---------------- Kotlin ----------------

_kt_header_re := `^\s*((?:(?:public|private|internal|protected|open|abstract|sealed|data|inner|value|enum|annotation|final)\s+)*)(class|object|interface)\s+\w+`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".kt")
	contains(content, "compareTo")
	lines := split(content, "\n")
	headers := [h | some h, l in lines; regex.match(_kt_header_re, l)]
	some i, line in lines
	regex.match(`^\s*(?:public\s+)?override\s+(?:operator\s+)?fun\s+compareTo\s*\(`, line)
	k := _enclosing(lines, headers, i)
	m := regex.find_all_string_submatch_n(_kt_header_re, lines[k], 1)
	m[0][2] != "interface"
	not regex.match(`\b(data|enum|value)\b`, m[0][1])
	h := split(_header_text(lines, k), "{")[0]
	not _kt_extends_class(h)
	e := _brace_end(lines, k)
	not _defines_in(lines, k, e, `\boverride\s+fun\s+equals\s*\(`)
	finding := _finding(path, i, line, "compareTo() is overridden without equals(); objects that compare as 0 are still unequal under == and in HashSet, so sorted and hashed collections disagree. Override equals (and hashCode) consistently with compareTo")
}

# A supertype list naming a constructor call (`: Base(), Comparable<T>`).
_kt_extends_class(h) if {
	m := regex.find_all_string_submatch_n(`(?:\b(?:class|object)\s+\w+|\))\s*:\s*([^:]*)$`, trim_space(_strip_generics(h)), 1)
	regex.match(`\w\s*\(`, m[0][1])
}

# ---------------- Python ----------------

_py_order_re := `^\s*def\s+__(lt|le|gt|ge)__\s*\(`

_py_body_end(lines, k) := e if {
	ik := _indent(lines[k])
	n := count(lines) - 1
	ends := [m | some m in numbers.range(k + 1, n); k + 1 <= n; trim_space(lines[m]) != ""; not _is_comment(lines[m]); _indent(lines[m]) <= ik]
	e := min(array.concat([n + 1], ends)) - 1
}

# No base class other than object or a metaclass keyword.
_py_plain_class(line) if regex.match(`^\s*class\s+\w+\s*(\(\s*(object|metaclass\s*=\s*[\w\.]+)?\s*\))?\s*:`, line)

_py_generated_eq(lines, k) if {
	some m in numbers.range(max([0, k - 3]), k - 1)
	k > 0
	regex.match(`^\s*@\s*(dataclasses\.)?dataclass\b|^\s*@\s*(attr|attrs)\.|^\s*@\s*(define|frozen|attrs|attr\.s|mutable)\b`, lines[m])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`def\s+__(lt|le|gt|ge)__`, content)
	lines := split(content, "\n")
	headers := [h | some h, l in lines; regex.match(`^\s*class\s+\w`, l)]
	some i, line in lines
	regex.match(_py_order_re, line)
	k := _enclosing(lines, headers, i)
	_py_plain_class(lines[k])
	not _py_generated_eq(lines, k)
	e := _py_body_end(lines, k)
	not _defines_in(lines, k, e, `^\s*def\s+__eq__\s*\(|^\s*__eq__\s*=`)
	not _earlier_order(lines, k, i)
	finding := _finding(path, i, line, "Ordering methods are defined without __eq__; objects that sort as equal still compare unequal with == and in sets and dicts. Define __eq__ (and __hash__) consistently with the ordering")
}

_earlier_order(lines, k, i) if {
	k + 1 <= i - 1
	some m in numbers.range(k + 1, i - 1)
	regex.match(_py_order_re, lines[m])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
