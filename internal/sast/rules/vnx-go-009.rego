package vulnetix.rules.vnx_go_009

import rego.v1

metadata := {
	"id": "VNX-GO-009",
	"name": "Go text/template used for HTML",
	"description": "Using text/template instead of html/template for web output does not escape HTML, enabling cross-site scripting (XSS) attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-009/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "template", "html"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`"text/template"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "text/template does not escape HTML; use html/template for web output to prevent XSS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
