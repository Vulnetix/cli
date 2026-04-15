package vulnetix.rules.vnx_node_011

import rego.v1

metadata := {
	"id": "VNX-NODE-011",
	"name": "Node.js server-side template injection",
	"description": "Passing user input directly to template engine render/compile functions (ejs.render, pug.render, Handlebars.compile) as the template string enables server-side template injection and remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-011/",
	"languages": ["node"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [1336],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssti", "template-injection", "ejs", "pug"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ssti_indicators := {
	"ejs.render(req.",
	"ejs.render(request.",
	"pug.render(req.",
	"pug.render(request.",
	"Handlebars.compile(req.",
	"Handlebars.compile(request.",
	"nunjucks.renderString(req.",
	"nunjucks.renderString(request.",
	"new Function(req.",
	"new Function(request.",
	"eval(req.",
	"eval(request.",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssti_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed as template string; use pre-compiled templates with user data as context variables only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
