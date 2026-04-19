# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_917

import rego.v1

metadata := {
	"id": "VNX-917",
	"name": "Expression Language (EL) injection",
	"description": "Incorporating user-controlled data into Expression Language expressions (SpEL, JSTL EL, Thymeleaf, Jinja2) allows attackers to evaluate arbitrary expressions, execute code, or access internal objects.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-917/",
	"languages": ["java", "python", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [917],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["el-injection", "ssti", "injection", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"render_template_string(",
	"Environment().from_string(",
	"jinja2.Template(",
	"parseExpression(userInput",
	"parseExpression(request",
	"parseExpression(param",
	"spelParser.parseExpression(",
	"ExpressionParser",
	"${param.",
	"__${",
	"th:text=\"${param",
	"th:utext=\"${",
	"th:href=\"${param",
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
		"message": sprintf("Expression Language injection risk: '%v' may evaluate user-controlled expressions — never embed untrusted data in EL templates", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
