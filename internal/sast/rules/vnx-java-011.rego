package vulnetix.rules.vnx_java_011

import rego.v1

metadata := {
	"id": "VNX-JAVA-011",
	"name": "Java expression language injection",
	"description": "Evaluating user-controlled input with SpEL (SpelExpressionParser), OGNL (OgnlUtil), or ScriptEngine enables remote code execution through expression language injection.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-011/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [917],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["el-injection", "spel", "ognl", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_el_injection_indicators := {
	"SpelExpressionParser()",
	"parseExpression(request",
	"parseExpression(req",
	"OgnlUtil",
	"Ognl.getValue(",
	"ScriptEngineManager()",
	"engine.eval(request",
	"engine.eval(req",
	"ExpressionFactory.createValueExpression(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _el_injection_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Expression language injection risk via %s; never evaluate user input as expressions", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
