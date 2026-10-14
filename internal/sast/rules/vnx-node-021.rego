package vulnetix.rules.vnx_node_021

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-021",
	"name": "XXE via libxmljs with noent:true",
	"description": "libxml2 is told to substitute entities while parsing, which turns on XML External Entity (XXE) processing: a document that declares <!ENTITY x SYSTEM \"file:///etc/passwd\"> gets the file's contents (or an internal URL's response) spliced in. Reported, in JavaScript and TypeScript files that import or require libxmljs, libxmljs2 or libxml2-wasm: a noent: true option (in the parseXml/parseXmlString call, across line breaks, or in an options object passed to it), and libxml2-wasm's ParseOption.XML_PARSE_NOENT flag. Not reported: noent: false or omitted (the libxml2 default leaves entities unexpanded), a noent key in a file that does not use libxml (fast-xml-parser, xml2js and sax never fetch external entities), comments and string literals. Leave noent off and do not combine dtdload with untrusted XML.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-021/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xxe", "xml", "libxmljs", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_strip(line) := regex.replace(line, "'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`)

# A quoted key ('noent': true) is unquoted first so stripping keeps it.
_noent(line) if {
	contains(line, "noent")
	regex.match(`\bnoent\s*:\s*true\b`, _strip(regex.replace(line, `'noent'|"noent"`, "noent")))
}

_noent(line) if {
	contains(line, "XML_PARSE_NOENT")
	regex.match(`\bXML_PARSE_NOENT\b`, _strip(line))
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`libxmljs|libxml2-wasm`, content)
	regex.match(`noent|XML_PARSE_NOENT`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`noent|NOENT`, line)
	not helpers.is_comment_line(line)
	_noent(line)
	finding := {
		"rule_id": metadata.id,
		"message": "libxml2 entity substitution (noent / XML_PARSE_NOENT) is enabled: untrusted XML can read local files or reach internal URLs through external entities (XXE). Leave noent off",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
