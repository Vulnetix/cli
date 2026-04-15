package vulnetix.rules.vnx_node_021

import rego.v1

metadata := {
	"id": "VNX-NODE-021",
	"name": "XXE via libxmljs with noent:true",
	"description": "libxmljs or libxmljs2 is parsing XML with noent set to true, enabling XML External Entity (XXE) processing. An attacker can supply a crafted XML document referencing external entities to read arbitrary files from the server (e.g. /etc/passwd) or trigger server-side request forgery. Set noent to false and avoid DTDLOAD when processing untrusted XML.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-021/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xxe", "xml", "libxmljs", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "noent")
	contains(line, "true")
	regex.match(`(libxmljs|parseXml|parseXmlString)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "libxmljs XML parsing with noent:true enables XXE; set noent:false and avoid DTDLOAD when parsing untrusted XML",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(libxmljs|libxmljs2)`, line)
	contains(line, "require(")
	finding := {
		"rule_id": metadata.id,
		"message": "libxmljs imported; ensure XML parsing is done with noent:false to prevent XXE attacks on untrusted XML input",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}
