package vulnetix.rules.vnx_java_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-005",
	"name": "Insecure deserialization",
	"description": "Reports Java deserialization of arbitrary object graphs: readObject()/readUnshared() on a java.io.ObjectInputStream created in the 40 lines above (or chained on new ObjectInputStream(...)) with no ObjectInputFilter set on it and no JVM-wide serial filter configured in the project; java.beans.XMLDecoder construction in a file that calls readObject(); XStream.fromXML() in a file that never restricts XStream types (allowTypes*, addPermission, setupDefaultSecurity, denyTypes); Jackson enableDefaultTyping() and activateDefaultTyping() with LaissezFaireSubTypeValidator; and SerializationUtils.deserialize(). Gadget chains in classpath libraries turn these into remote code execution when the bytes come from outside. Not reported: the in-memory deep-copy idiom (an ObjectInputStream or SerializationUtils.deserialize over bytes the same code just serialised), a subclass with its own resolveClass check (LookAheadObjectInputStream, ValidatingObjectInputStream), a custom readObject(ObjectInputStream) method calling in.defaultReadObject(), Jackson activateDefaultTyping with a restrictive PolymorphicTypeValidator, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-005/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "dangerous-function", "rce"],
}

_strip(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg := "Untrusted bytes deserialized into arbitrary Java objects; use a data format (JSON) or set an ObjectInputFilter allowlist before readObject()"

# A JVM-wide serial filter configured anywhere in the project.
_global_filter if {
	some p, c in input.file_contents
	endswith(p, ".java")
	contains(c, "setSerialFilter")
}

_global_filter if {
	some p, c in input.file_contents
	contains(c, "jdk.serialFilter")
}

_window(lines, a, b) := concat("\n", [lines[k] |
	some k in numbers.range(max([0, a]), min([count(lines) - 1, b]))
	not helpers.is_comment_line(lines[k])
])

# Bytes the same code serialised a few lines earlier (deep copy).
_deep_copy(win) if {
	contains(win, "ObjectOutputStream")
	contains(win, "toByteArray()")
}

_deep_copy(win) if regex.match(`SerializationUtils\.serialize\s*\(`, win)

# ── ObjectInputStream.readObject() ───────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "new ObjectInputStream")
	not _global_filter
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.read(?:Object|Unshared)\s*\(\s*\)`, line)
	not helpers.is_comment_line(line)
	sline := _strip(line)
	m := regex.find_all_string_submatch_n(`(?:\b([A-Za-z_]\w*)|(new\s+ObjectInputStream\s*\(.*\)))\s*\.read(?:Object|Unshared)\s*\(\s*\)`, sline, 1)
	count(m) > 0
	_ois_unfiltered(lines, i, m[0][1], m[0][2])
	finding := _finding(path, i, line, _msg)
}

# chained: new ObjectInputStream(in).readObject()
_ois_unfiltered(lines, i, "", chained) if {
	chained != ""
	not _deep_copy(_window(lines, i - 15, i))
}

_ois_unfiltered(lines, i, v, "") if {
	v != ""
	some j in numbers.range(max([0, i - 40]), i)
	contains(lines[j], v)
	not helpers.is_comment_line(lines[j])
	decl := _strip(concat(" ", [lines[j], lines[min([count(lines) - 1, j + 1])]]))
	regex.match(concat("", [`\b`, v, `\s*=\s*new\s+ObjectInputStream\s*\(`]), decl)
	not _filtered(lines, j, i, v)
	not _deep_copy(_window(lines, j - 15, i))
}

_filtered(lines, j, i, v) if {
	some k in numbers.range(j, i)
	regex.match(concat("", [`\b`, v, `\s*\.\s*setObjectInputFilter\s*\(`]), lines[k])
}

# ── XMLDecoder ───────────────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "XMLDecoder")
	contains(content, "readObject")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "XMLDecoder")
	not helpers.is_comment_line(line)
	regex.match(`new\s+(?:java\.beans\.)?XMLDecoder\s*\(`, _strip(line))
	finding := _finding(path, i, line, "java.beans.XMLDecoder instantiates any class and calls any method the XML names; never decode untrusted XML with it")
}

# ── XStream ──────────────────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "XStream")
	contains(content, "fromXML")
	not regex.match(`\.(?:allowTypes\w*|allowTypeHierarchy|addPermission|setupDefaultSecurity|denyTypes\w*)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "fromXML")
	not helpers.is_comment_line(line)
	regex.match(`\.fromXML\s*\(`, _strip(line))
	finding := _finding(path, i, line, "XStream.fromXML() without a type allowlist deserializes arbitrary classes; call xstream.allowTypes(...) (or addPermission) for the expected types only")
}

# ── Jackson polymorphic default typing ───────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "DefaultTyping")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "DefaultTyping")
	not helpers.is_comment_line(line)
	_unsafe_typing(lines, i, _strip(line))
	finding := _finding(path, i, line, "Jackson default typing lets the JSON choose the class to instantiate; remove it or use activateDefaultTyping with a BasicPolymorphicTypeValidator that allows only your types")
}

_unsafe_typing(_, _, sline) if regex.match(`\.enableDefaultTyping\s*\(`, sline)

_unsafe_typing(lines, i, sline) if {
	regex.match(`\.activateDefaultTyping\s*\(`, sline)
	contains(_window(lines, i, i + 3), "LaissezFaireSubTypeValidator")
}

# ── SerializationUtils.deserialize ───────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "SerializationUtils")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "deserialize")
	not helpers.is_comment_line(line)
	regex.match(`\bSerializationUtils\s*\.\s*deserialize\s*\(`, _strip(line))
	not _deep_copy(_window(lines, i - 10, i))
	finding := _finding(path, i, line, _msg)
}
