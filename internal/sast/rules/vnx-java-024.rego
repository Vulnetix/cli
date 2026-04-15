package vulnetix.rules.vnx_java_024

import rego.v1

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
	content := input.file_contents[path]
	contains(content, "DocumentBuilderFactory.newInstance()")
	not contains(content, "disallow-doctype-decl")
	not contains(content, "setExpandEntityReferences(false)")
	lines := split(content, "\n")
	some i, line in lines
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
	content := input.file_contents[path]
	contains(content, "SAXParserFactory.newInstance()")
	not contains(content, "disallow-doctype-decl")
	not contains(content, "setFeature")
	lines := split(content, "\n")
	some i, line in lines
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
