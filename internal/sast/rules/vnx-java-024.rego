package vulnetix.rules.vnx_java_024

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-024",
	"name": "Java XML entity expansion (Billion Laughs) — DTD not disabled",
	"description": "DocumentBuilderFactory or SAXParserFactory is used without disabling DOCTYPE declarations or entity expansion. An attacker can supply an XML document with recursively-nested entity references that expand exponentially, exhausting server memory (Billion Laughs / XML bomb attack).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-024/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [776],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xml", "xxe", "dos", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	# The hardening check runs over code only. A comment such as
	# "// TRIGGERS: ... without disallow-doctype-decl" names the mitigation
	# without applying it, and used to suppress the finding it described.
	code := helpers.code_text(lines)
	contains(code, "DocumentBuilderFactory.newInstance()")
	not contains(code, "disallow-doctype-decl")
	not contains(code, "setExpandEntityReferences(false)")
	some i, line in lines
	not helpers.is_comment_line(line)
	contains(line, "DocumentBuilderFactory.newInstance()")
	finding := {
		"rule_id": metadata.id,
		"message": "DocumentBuilderFactory used without disabling DOCTYPE declarations; set feature 'http://apache.org/xml/features/disallow-doctype-decl' to true to prevent XML entity expansion (Billion Laughs)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	code := helpers.code_text(lines)
	contains(code, "SAXParserFactory.newInstance()")
	not contains(code, "disallow-doctype-decl")
	not contains(code, "setFeature")
	some i, line in lines
	not helpers.is_comment_line(line)
	contains(line, "SAXParserFactory.newInstance()")
	finding := {
		"rule_id": metadata.id,
		"message": "SAXParserFactory used without security features; disable DOCTYPE declarations to prevent XML entity expansion attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
