package vulnetix.rules.vnx_java_004

import rego.v1

metadata := {
	"id": "VNX-JAVA-004",
	"name": "XML external entity (XXE) injection",
	"description": "XML parsers without secure processing features can resolve external entities, enabling file disclosure, SSRF, and denial of service via entity expansion.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-004/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-201"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xxe", "xml", "injection", "ssrf"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_xxe_indicators := {
	"DocumentBuilderFactory.newInstance()",
	"SAXParserFactory.newInstance()",
	"XMLInputFactory.newInstance()",
	"TransformerFactory.newInstance()",
	"SchemaFactory.newInstance(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	content := input.file_contents[path]
	some indicator in _xxe_indicators
	contains(content, indicator)
	not contains(content, "disallow-doctype-decl")
	not contains(content, "FEATURE_SECURE_PROCESSING")
	not contains(content, "external-general-entities")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("XML parser (%s) without XXE protection; set disallow-doctype-decl or disable external entities", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
