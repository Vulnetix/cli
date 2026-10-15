# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_582

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-582",
	"name": "Array declared public, final and static",
	"description": "A public static final array field: Java in any modifier order, with [] on the type or on the name, initialised inline or later in a static block, an array constant in a Java interface (implicitly public static final; files whose only top-level type is an interface, at the interface's member indent), and C# public static readonly T[]. final (readonly) fixes the reference, not the elements, so any code can overwrite the shared array's contents. Not reported: private, protected or package-private fields, non-final fields (a different weakness), zero-length arrays (new T[0], {}, new T[] {}, Array.Empty<T>(), []), collections and read-only list types, methods returning arrays, comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-582/",
	"languages": ["java", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [582],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["array-public", "cwe-582"],
}

# Field declaration: annotations, modifiers, a type, then [] on the type
# (group 2) or on the name (group 3), then an initialiser or `;` (group 4).
# A method (`int[] values() {`) has `(` after the name and never matches.
_java_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|static|final|transient|volatile)\s+)+)[\w.$]+(?:<[^=;()]*>)?((?:\s*\[\s*\])*)\s+\w+((?:\s*\[\s*\])*)\s*(=.*|;.*)$`

_cs_re := `^\s*(?:\[[^\]]*\]\s*)*((?:(?:public|protected|private|internal|static|readonly|new|volatile)\s+)+)[\w.]+(?:<[^=;()]*>)?((?:\s*\[\s*,*\s*\])+)\s*\w+()\s*(=.*|;.*)$`

# A zero-length array has no elements to overwrite.
_empty_init(rest) if regex.match(`^=\s*(?:\{\s*\}|\[\s*\]|new\s+[\w.]+\s*\[\s*0\s*\]|new\s+[\w.<>?]+\s*\[\s*\]\s*\{\s*\}|(?:System\.)?Array\.Empty<[^>]*>\(\s*\))\s*;`, rest)

_decl(path, line) := m if {
	endswith(path, ".java")
	m := regex.find_all_string_submatch_n(_java_re, line, 1)[0]
	regex.match(`\bfinal\b`, m[1])
}

_decl(path, line) := m if {
	endswith(path, ".cs")
	m := regex.find_all_string_submatch_n(_cs_re, line, 1)[0]
	regex.match(`\breadonly\b`, m[1])
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".cs")

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "[")
	regex.match(`\bpublic\b[^\n;=(]*\bstatic\b|\bstatic\b[^\n;=(]*\bpublic\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "static")
	contains(line, "public")
	contains(line, "[")
	not helpers.is_comment_line(line)
	m := _decl(path, line)
	regex.match(`\bpublic\b`, m[1])
	regex.match(`\bstatic\b`, m[1])
	concat("", [m[2], m[3]]) != ""
	not _empty_init(m[4])
	finding := {
		"rule_id": metadata.id,
		"message": "public static final array: final fixes the reference, not the elements, so any caller can modify the shared array. Make it private and expose an unmodifiable List or a defensive copy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Interface constants are implicitly public static final. A file whose only
# top-level type is an interface: a field at the interface's member indent
# (the indent of the first code line after the declaration) with an array
# type and an initialiser. Locals in default methods sit one level deeper.
_iface_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|static|final)\s+)*[\w.$]+(?:<[^=;()]*>)?((?:\s*\[\s*\])*)\s+\w+((?:\s*\[\s*\])*)\s*(=.*)$`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "[")
	regex.match(`(?m)^(?:public\s+)?interface\s+\w+`, content)
	not regex.match(`(?m)^(?:[\w@]+\s+)*(?:class|enum|record)\s+\w+`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	decls := [k | some k, l in lines; regex.match(`^(?:public\s+)?interface\s+\w+`, l)]
	d := decls[0]
	first := helpers.next_code_index(lines, d, 20)
	unit := regex.find_n(`^[ \t]+`, lines[first], 1)[0]
	some i, line in lines
	i > d
	contains(line, "[")
	contains(line, "=")
	startswith(line, unit)
	not regex.match(`^\s`, substring(line, count(unit), 1))
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_iface_re, line, 1)[0]
	concat("", [m[1], m[2]]) != ""
	not _empty_init(m[3])
	finding := {
		"rule_id": metadata.id,
		"message": "Array constant in an interface is implicitly public static final: final fixes the reference, not the elements, so any caller can modify the shared array. Expose an unmodifiable List or a defensive copy instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
