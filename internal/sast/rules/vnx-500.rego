# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_500

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-500",
	"name": "Public Static Field Not Marked Final",
	"description": "A field declared public and static without final (Java) or without readonly/const (C#), in any modifier order and with or without an annotation or initialiser. Any code in the process can reassign it, so a value other classes rely on (a configuration flag, a singleton, a trusted-host list, a connection string) can be replaced at run time. Reported on the declaration. Not reported: public static final / static readonly / const fields, non-public statics, methods, nested classes, generic methods, C# properties, expression-bodied members and events, fields of a Java interface (implicitly final), test code, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-500/",
	"languages": ["java", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [500],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["static-non-final", "cwe-500"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "cs" if endswith(path, ".cs")

# Modifiers, a type (generic and array forms), a name, then `=`, `;` or `,`:
# a method has `(` after its name, a property `{`, a class `class`.
_decl_re := {
	"java": `^\s*(?:@\w+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|static|final|volatile|transient)\s+)+)([\w.]+(?:\s*<[^;=()]*>)?(?:\s*\[\s*\])*)\s+(\w+)\s*(?:=[^=>]|;|,)`,
	"cs": `^\s*(?:\[[^\]]*\]\s*)*((?:(?:public|protected|private|internal|static|readonly|const|volatile|new|unsafe)\s+)+)([\w.]+(?:\s*<[^;=()]*>)?(?:\s*\[[\s,]*\])*\??)\s+(\w+)\s*(?:=[^=>]|;|,)`,
}

_immutable := {"java": `\bfinal\b`, "cs": `\b(?:readonly|const)\b`}

_not_a_type := {"class", "interface", "enum", "record", "struct", "event", "delegate", "void", "abstract", "synchronized", "native"}

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# Fields of an interface are implicitly public static final.
_interface_only("java", content) if {
	regex.match(`(?m)^\s*(?:public\s+)?(?:@)?interface\s+\w+`, content)
	not regex.match(`(?m)^\s*(?:(?:public|protected|private|abstract|final|static)\s+)*(?:class|enum|record)\s+\w+`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, "public")
	regex.match(`static\s`, content)
	not helpers.is_test_path(path)
	not regex.match(`(?:^|/)[^/]*Tests?\.cs$`, path)
	not _interface_only(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "static")
	contains(line, "public")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl_re[lang], _code(line), 1)[0]
	mods := m[1]
	regex.match(`\bpublic\b`, mods)
	regex.match(`\bstatic\b`, mods)
	not regex.match(_immutable[lang], mods)
	not m[2] in _not_a_type
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public static field '%s' is not final: any code can reassign it. Make it final (readonly in C#) or private behind an accessor", [m[3]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
