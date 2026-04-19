# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_611

import rego.v1

metadata := {
	"id": "VNX-611",
	"name": "XML External Entity (XXE) Injection",
	"description": "XML parsers that process external entity references allow attackers to read arbitrary files, perform SSRF, or cause denial of service. Disable DTD processing and external entity resolution in all XML parsers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-611/",
	"languages": ["python", "java", "php", "node", "csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xxe", "xml", "injection", "file-disclosure"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"xml.etree.ElementTree.parse(",
	"xml.etree.ElementTree.fromstring(",
	"lxml.etree.parse(",
	"lxml.etree.fromstring(",
	"DocumentBuilderFactory.newInstance()",
	"SAXParserFactory.newInstance()",
	"XMLInputFactory.newInstance()",
	"simplexml_load_string(",
	"simplexml_load_file(",
	"DOMDocument->loadXML(",
	"xml2js.parseString(",
	"libxmljs.parseXml(",
	"noent: true",
	"XmlReader.Create(",
	"new XmlDocument(",
	"DtdProcessing.Parse",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential XXE vulnerability: '%v' may process external entities — disable DTD/external entity processing", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
