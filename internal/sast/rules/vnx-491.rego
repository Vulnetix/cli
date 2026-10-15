# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_491

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-491",
	"name": "Public cloneable() Method Without Final ('Object Hijack')",
	"description": "A Java class that is not final declares a public clone() that is not final and builds its copy with super.clone() within the next few lines. super.clone() creates the object without running a constructor, and because neither the class nor the method is final, a subclass can override clone() and hand out copies that skip the constructor's checks or share mutable internals. Not reported: a final clone() (including one that only throws CloneNotSupportedException), a clone() in a final class or record, a clone() that copies through a constructor rather than super.clone(), a clone overload with parameters, non-public clone methods, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-491/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [491],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["clone", "object-hijack", "final", "cwe-491"],
}

_clone_re := `^\s*(?:@\w+\s+)*((?:(?:public|protected|private|static|final|synchronized|native|strictfp|abstract)\s+)*)[\w.<>\[\], ?]+\s+clone\s*\(\s*\)`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# The class enclosing line i: the nearest class/enum/record declaration above
# it at a smaller indent.
_enclosing_type(lines, i) := lines[k] if {
	ii := _indent(lines[i])
	ks := [k |
		some k in numbers.range(0, i - 1)
		k < i
		_indent(lines[k]) < ii
		regex.match(`^\s*(?:\S.*\s)?(?:class|enum|record|interface)\s+\w+`, lines[k])
		not helpers.is_comment_line(lines[k])
	]
	count(ks) > 0
	k := ks[count(ks) - 1]
}

_final_type(decl) if regex.match(`\bfinal\s+(?:\w+\s+)*class\b`, decl)

_final_type(decl) if regex.match(`\b(?:enum|record|interface)\s+\w+`, decl)

_uses_super_clone(lines, i) if {
	some j in numbers.range(i, min([count(lines) - 1, i + 12]))
	contains(lines[j], "super.clone()")
	not helpers.is_comment_line(lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "super.clone()")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "clone")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_clone_re, _code(line), 1)
	count(m) > 0
	mods := m[0][1]
	regex.match(`\bpublic\b`, mods)
	not regex.match(`\bfinal\b`, mods)
	_uses_super_clone(lines, i)
	decl := _enclosing_type(lines, i)
	not _final_type(decl)
	finding := {
		"rule_id": metadata.id,
		"message": "Public clone() is neither final nor in a final class and copies via super.clone(), which skips the constructor; a subclass can override it. Declare clone() (or the class) final, or copy through a constructor",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
