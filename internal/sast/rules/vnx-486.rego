# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_486

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-486",
	"name": "Comparison of Classes by Name",
	"description": "An object's type is decided by comparing its class name: in Java, getClass().getName(), getSimpleName() or getCanonicalName() (or Foo.class.getName()) compared with equals/equalsIgnoreCase/== in either order; in C#, GetType().Name or GetType().FullName compared with ==, != or Equals; in Python, type(x).__name__ or x.__class__.__name__ compared with ==, != or in. A switch (C# switch expression, Python match) on such a name is reported, as is a class name stored in a local and compared with a literal within the next eight lines. Different classes can share a name (another package, another class loader, an attacker-supplied subclass or plugin), so a trust or dispatch decision made this way can be satisfied by the wrong type. Not reported: instanceof, isinstance, is, isAssignableFrom and class-object identity (getClass() == Foo.class, GetType() == typeof(Foo), type(x) is Foo), a class name read for logging or display, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-486/",
	"languages": ["java", "csharp", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [486],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["class-comparison", "type-confusion", "cwe-486"],
}

_java_name := `(?:\.getClass\(\)|\.class)\.get(?:Simple|Canonical|Type)?Name\(\)`

_cs_name := `\.GetType\(\)\.(?:Full)?Name\b`

_py_name := `(?:\btype\([^()]*\)|\.__class__)\.__(?:qual)?name__`

_name_expr := {".java": _java_name, ".cs": _cs_name, ".py": _py_name}

_patterns := {
	".java": [
		concat("", [_java_name, `\s*(?:\.equals(?:IgnoreCase)?\s*\(|[!=]=)`]),
		concat("", [`(?:\.equals(?:IgnoreCase)?\s*\(|[!=]=)\s*[\w.]*`, `(?:\([^()]*\))?`, _java_name]),
		concat("", [`\bswitch\s*\([^;]*`, _java_name]),
	],
	".cs": [
		`\.GetType\(\)\.(?:Full)?Name\s*(?:[!=]=|\.Equals\s*\(|switch\b)`,
		`(?:[!=]=|\.Equals\s*\()\s*[\w.]*(?:\([^()]*\))?\.GetType\(\)\.(?:Full)?Name\b`,
		`\bstring\.Equals\s*\([^;]*\.GetType\(\)\.(?:Full)?Name\b`,
		`\bswitch\s*\([^;]*\.GetType\(\)\.(?:Full)?Name\b`,
	],
	".py": [
		`(?:\btype\([^()]*\)|\.__class__)\.__(?:qual)?name__\s*(?:[!=]=|\bnot\s+in\b|\bin\b)`,
		`(?:[!=]=)\s*(?:type\([^()]*\)|[\w.]+\.__class__)\.__(?:qual)?name__`,
		`^\s*match\s+(?:type\([^()]*\)|[\w.]+\.__class__)\.__(?:qual)?name__\s*:`,
	],
}

_needle := {".java": "Name()", ".cs": "GetType()", ".py": "name__"}

# String literals are blanked so a quoted example is not a comparison.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Type decided by comparing a class name; a different class with the same name passes. Compare class objects (instanceof, isinstance, getClass() == Foo.class) instead",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	some ext, pats in _patterns
	endswith(path, ext)
	contains(content, _needle[ext])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _needle[ext])
	not helpers.is_comment_line(line)
	c := _code(line)
	some p in pats
	regex.match(p, c)
	finding := _finding(path, i, line)
}

# Two lines: the class name is stored in a local, and the local is compared
# with a literal within the next eight lines.
_assign_re := {
	".java": concat("", [`^\s*(?:final\s+)?(?:(?:String|var)\s+)?(\w+)\s*=\s*[\w.()\[\]]*`, _java_name, `\s*;`]),
	".cs": concat("", [`^\s*(?:(?:string|var)\s+)?(\w+)\s*=\s*[\w.()\[\]]*`, _cs_name, `\s*;`]),
	".py": concat("", [`^\s*(\w+)\s*=\s*[\w.()\[\]]*`, _py_name, `\s*(?:#.*)?$`]),
}

_compare_re(".java", v) := concat("", [`\b`, v, `\.equals(?:IgnoreCase)?\s*\(\s*"|"\.equals(?:IgnoreCase)?\s*\(\s*`, v, `\s*\)|\b`, v, `\s*[!=]=\s*"|"\s*[!=]=\s*`, v, `\b|\bswitch\s*\(\s*`, v, `\s*\)`])

_compare_re(".cs", v) := concat("", [`\b`, v, `\s*[!=]=\s*"|"\s*[!=]=\s*`, v, `\b|\b`, v, `\.Equals\s*\(\s*"|\bswitch\s*\(\s*`, v, `\s*\)|\bstring\.Equals\s*\(\s*`, v, `\b|\b`, v, `\s+switch\b`])

_compare_re(".py", v) := concat("", [`\b`, v, `\s*[!=]=\s*['"]|['"]\s*[!=]=\s*`, v, `\b|\b`, v, `\s+(?:not\s+)?in\s*[(\[{]|^\s*match\s+`, v, `\s*:`])

findings contains finding if {
	some path, content in input.file_contents
	some ext, are in _assign_re
	endswith(path, ext)
	contains(content, _needle[ext])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _needle[ext])
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(are, line, 1)
	v := m[0][1]
	cre := _compare_re(ext, v)
	some j in numbers.range(i + 1, min([i + 8, count(lines) - 1]))
	not helpers.is_comment_line(lines[j])
	regex.match(cre, _code(lines[j]))
	finding := _finding(path, j, lines[j])
}
