# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_915

import rego.v1

metadata := {
	"id": "VNX-915",
	"name": "Mass assignment / improperly controlled object attribute modification",
	"description": "Passing user-controlled data directly to model update methods allows attackers to set arbitrary attributes, including privileged fields like admin flags or ownership identifiers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-915/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-77"],
	"attack_technique": ["T1565"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["mass-assignment", "injection", "privilege-escalation"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"params.permit!",
	"update_attributes(params",
	"update_attributes(params[",
	"update(params[",
	"Object.assign(model, req.body",
	"Object.assign(user, req.body",
	"Object.assign(obj, req.body",
	"_.extend(model, req.body",
	"_.merge(model, req.body",
	"fill(request->all()",
	"fill($request->all()",
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
		"message": sprintf("Mass assignment risk: '%v' applies unfiltered user input to model attributes — use an explicit allowlist of permitted fields", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
