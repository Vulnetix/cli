# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_95

import rego.v1

metadata := {
	"id": "VNX-95",
	"name": "Template Injection (Eval Injection)",
	"description": "User-controlled data is passed to a server-side template engine for rendering. An attacker can inject template directives to read files, environment variables, or execute arbitrary code on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-95/",
	"languages": ["node", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [95],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["template-injection", "ssti", "eval-injection", "cwe-95"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Python template engines — dangerous when rendering user-supplied strings
_python_template_patterns := {
	"render_template_string(",
	"Template(",
	"Environment().from_string(",
	"env.from_string(",
	"jinja2.Template(",
	"mako.template.Template(",
	"Mako.Template(",
	"string.Template(",
}

# Node.js template engines rendering user input
_node_template_patterns := {
	"pug.render(",
	"pug.compile(",
	"ejs.render(",
	"ejs.compile(",
	"handlebars.compile(",
	"Handlebars.compile(",
	"nunjucks.renderString(",
	"swig.render(",
	"mustache.render(",
	"dot.template(",
	"jade.render(",
	"jade.compile(",
	"consolidate.",
}

# Ruby ERB with user input
_ruby_template_patterns := {
	"ERB.new(",
	"Erubi::Engine.new(",
	"Liquid::Template.parse(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_template_patterns
	contains(line, pattern)
	_has_user_controlled_variable(line)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Server-side template injection: '%s' called with user-controlled input; use render_template() with a static template file and pass data as context variables", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Flag all uses of render_template_string — it is almost always wrong
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "render_template_string(")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": "render_template_string() renders a template from an arbitrary string; if that string contains any user input, SSTI is possible. Use render_template() with static template files",
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
	_is_js_ts(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _node_template_patterns
	contains(line, pattern)
	_has_user_controlled_variable(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node.js template injection: '%s' called with user-controlled data; precompile templates from static files and pass user data as context variables only", [pattern]),
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
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _ruby_template_patterns
	contains(line, pattern)
	_has_user_controlled_variable(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Ruby template injection: '%s' with user-controlled input; never pass user data as the template source — only as binding variables", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby ERB.new with .result — flag when user input is nearby
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "ERB.new(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": "ERB.new() renders a template from a string; if user input reaches this string, SSTI/code execution is possible. Use static template files loaded from disk",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_js_ts(path) if endswith(path, ".js")
_is_js_ts(path) if endswith(path, ".ts")
_is_js_ts(path) if endswith(path, ".jsx")
_is_js_ts(path) if endswith(path, ".tsx")
_is_js_ts(path) if endswith(path, ".mjs")
_is_js_ts(path) if endswith(path, ".cjs")

_has_user_controlled_variable(line) if contains(line, "request")
_has_user_controlled_variable(line) if contains(line, "req.")
_has_user_controlled_variable(line) if contains(line, "params")
_has_user_controlled_variable(line) if contains(line, "input")
_has_user_controlled_variable(line) if contains(line, "user_input")
_has_user_controlled_variable(line) if contains(line, "userInput")
_has_user_controlled_variable(line) if contains(line, "body")
_has_user_controlled_variable(line) if contains(line, "query")
_has_user_controlled_variable(line) if contains(line, "data")
_has_user_controlled_variable(line) if contains(line, "template_str")
_has_user_controlled_variable(line) if contains(line, "tmpl_str")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
