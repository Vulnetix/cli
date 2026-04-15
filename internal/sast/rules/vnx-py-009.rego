package vulnetix.rules.vnx_py_009

import rego.v1

metadata := {
	"id": "VNX-PY-009",
	"name": "Jinja2 autoescape disabled",
	"description": "Jinja2 Environment with autoescape=False renders templates without HTML escaping, enabling cross-site scripting (XSS) when user input is included in templates.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-009",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "jinja2", "template", "web"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Environment\(.*autoescape\s*=\s*False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Jinja2 autoescape disabled; enable autoescape=True or use select_autoescape() to prevent XSS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
