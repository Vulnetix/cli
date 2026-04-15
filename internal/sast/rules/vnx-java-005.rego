package vulnetix.rules.vnx_java_005

import rego.v1

metadata := {
	"id": "VNX-JAVA-005",
	"name": "Insecure deserialization",
	"description": "ObjectInputStream.readObject() deserializes arbitrary Java objects. Malicious serialized data can execute arbitrary code during deserialization via gadget chains.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-005/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "dangerous-function", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_deser_indicators := {
	"ObjectInputStream",
	"readObject()",
	"readUnshared()",
	"XMLDecoder",
	"enableDefaultTyping()",
	"activateDefaultTyping(",
	"XStream",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _deser_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure deserialization (%s); use allowlisting, JSON serialization, or a look-ahead ObjectInputStream", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
