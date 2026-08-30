package vulnetix.rules.vnx_cs_005

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-005",
	"name": "C# missing ValidateAntiForgeryToken on state-changing MVC actions",
	"description": "An ASP.NET MVC controller method that performs state-changing operations (POST, PUT, DELETE, PATCH) lacks the [ValidateAntiForgeryToken] attribute. Without anti-CSRF token validation the endpoint is vulnerable to Cross-Site Request Forgery.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-005/",
	"languages": ["csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [352],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csrf", "mvc", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

# Look for HttpPost/HttpPut/HttpDelete/HttpPatch attribute without ValidateAntiForgeryToken nearby
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\[Http(Post|Put|Delete|Patch)\]`, line)
	not helpers.is_comment_line(line)
	# Check the surrounding context (10 lines) for missing VAFT. Comments are
	# stripped first: a `// TODO: add [ValidateAntiForgeryToken]` note is a
	# description of the vulnerability, not the mitigation, and it used to
	# silence this rule.
	window := helpers.code_window(lines, i, 2, 10)
	not contains(window, "ValidateAntiForgeryToken")
	not contains(window, "Consumes(")
	not contains(window, "IgnoreAntiforgeryToken")
	finding := {
		"rule_id": metadata.id,
		"message": "State-changing MVC action missing [ValidateAntiForgeryToken]; add the attribute or use [AutoValidateAntiforgeryToken] at the controller level to prevent CSRF",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
