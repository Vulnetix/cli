package vulnetix.rules.vnx_cs_003

import rego.v1

metadata := {
	"id": "VNX-CS-003",
	"name": "C# XXE via XmlDocument with XmlResolver enabled",
	"description": "XmlDocument or XmlTextReader is configured with an XmlUrlResolver or without explicitly disabling DTD processing. This permits XML External Entity (XXE) injection that can read local files or trigger SSRF.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-003/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xxe", "xml", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

# Detect XmlResolver set to XmlUrlResolver (enables XXE)
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "XmlResolver")
	contains(line, "XmlUrlResolver")
	finding := {
		"rule_id": metadata.id,
		"message": "XmlResolver set to XmlUrlResolver; set XmlResolver = null to disable external entity resolution and prevent XXE",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect DtdProcessing.Parse
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "DtdProcessing")
	contains(line, "Parse")
	finding := {
		"rule_id": metadata.id,
		"message": "DtdProcessing.Parse enables DTD processing; use DtdProcessing.Prohibit to prevent XXE injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect XmlTextReader with ProhibitDtd = false
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "ProhibitDtd")
	contains(line, "false")
	finding := {
		"rule_id": metadata.id,
		"message": "ProhibitDtd set to false enables DTD processing; set ProhibitDtd = true or use XmlReaderSettings with DtdProcessing.Prohibit to prevent XXE",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
