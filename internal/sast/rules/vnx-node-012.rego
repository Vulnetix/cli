package vulnetix.rules.vnx_node_012

import rego.v1

metadata := {
	"id": "VNX-NODE-012",
	"name": "Client-side XSS via innerHTML or v-html",
	"description": "Using innerHTML, outerHTML, document.write, jQuery .html(), or Vue v-html with dynamic content enables cross-site scripting (XSS) attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-012/",
	"languages": ["node"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "dom", "client-side"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_xss_indicators := {
	".innerHTML =",
	".innerHTML=",
	".outerHTML =",
	".outerHTML=",
	"document.write(",
	"document.writeln(",
	"v-html=",
	"dangerouslySetInnerHTML",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _xss_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic content in innerHTML/v-html enables XSS; use textContent or framework-safe bindings instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\$\(.*\)\.html\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Dynamic content in innerHTML/v-html enables XSS; use textContent or framework-safe bindings instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
