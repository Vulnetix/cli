package vulnetix.rules.vnx_py_014

import rego.v1

metadata := {
	"id": "VNX-PY-014",
	"name": "Python XML external entity injection",
	"description": "Python's xml.etree.ElementTree, xml.dom.minidom, and lxml.etree parsers are vulnerable to XXE attacks by default. Use defusedxml or disable external entity processing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-014/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [611],
	"capec": ["CAPEC-201"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xxe", "xml", "injection", "python"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_xxe_indicators := {
	"ElementTree.parse(",
	"ET.parse(",
	"etree.parse(",
	"minidom.parse(",
	"minidom.parseString(",
	"etree.fromstring(",
	"ET.fromstring(",
	"ElementTree.fromstring(",
	"xml.sax.parse(",
	"xml.sax.parseString(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _xxe_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("XML parser %s is vulnerable to XXE; use defusedxml or disable external entity processing", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
