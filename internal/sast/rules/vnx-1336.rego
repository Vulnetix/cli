# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1336

import rego.v1

metadata := {
	"id": "VNX-1336",
	"name": "Improper Neutralization of Special Elements Used in a Template Engine (Server-Side Template Injection)",
	"description": "User-controlled input is passed directly to a server-side template engine for rendering. This allows an attacker to inject template syntax that executes arbitrary code, reads environment variables and files, or achieves remote code execution on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1336/",
	"languages": ["python", "javascript", "java", "ruby", "php", "go"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [1336],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssti", "template-injection", "jinja2", "pug", "erb", "thymeleaf", "cwe-1336"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Python Flask/Jinja2: render_template_string with user input
_py_ssti_patterns := {
	"render_template_string(",
	"jinja2.Template(",
	"Environment().from_string(",
	"Template(request.",
	"Template(user_",
	"from_string(request.",
	"from_string(user_",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _py_ssti_patterns
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Server-side template injection risk: '%s' renders user-controlled template string; use render_template() with a static template file and pass data as variables — never render user-supplied template syntax", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js: pug/jade render with user template
_node_ssti_patterns := {
	"pug.render(",
	"pug.compile(",
	"jade.render(",
	"jade.compile(",
	"nunjucks.renderString(",
	"ejs.render(",
	"handlebars.compile(",
	"Handlebars.compile(",
	"mustache.render(",
	"swig.render(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _node_ssti_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential SSTI: '%s' may compile/render user-controlled template strings; pass user data as template variables rather than as the template source itself", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: SpEL expression from user input
_java_ssti_patterns := {
	"SpelExpressionParser(",
	"parseExpression(",
	"ExpressionParser",
	"StandardEvaluationContext",
	"Velocity.evaluate(",
	"new VelocityEngine(",
	"FreeMarker",
	"Template template = cfg.getTemplate(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_ssti_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential SSTI: Java template/expression engine '%s' detected; ensure user input is never used as the expression or template source — pass data only as model variables in a pre-defined template", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby: ERB with user input
_ruby_ssti_patterns := {
	"ERB.new(",
	"Erubi::Engine.new(",
	"Liquid::Template.parse(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _ruby_ssti_patterns
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential SSTI: Ruby template engine '%s' detected; if the template source is user-controlled this allows arbitrary Ruby code execution — use pre-defined template files and pass data as variables", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Go: template/text rendering with user-supplied template string
_go_ssti_patterns := {
	"template.New(",
	"html/template",
	"text/template",
	"t.Parse(",
	"tmpl.Parse(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _go_ssti_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Go template operation '%s' detected; if user data is passed as the template source string rather than as data, an attacker can inject template actions — always use static template files", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
