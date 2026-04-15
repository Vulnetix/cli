package vulnetix.rules.vnx_py_008

import rego.v1

metadata := {
	"id": "VNX-PY-008",
	"name": "Flask debug mode enabled",
	"description": "Flask app.run(debug=True) enables the Werkzeug interactive debugger, which allows remote code execution on the server via the debugger console.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-008/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [489],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["flask", "debug", "config", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.run\(.*debug\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Flask debug mode enabled; the Werkzeug debugger allows RCE — disable in production",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
