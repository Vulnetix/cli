# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_94

import rego.v1

metadata := {
	"id": "VNX-94",
	"name": "Code Injection",
	"description": "User-controlled data is passed to a dynamic code evaluation function such as eval(), exec(), or compile(). An attacker can inject arbitrary code that runs in the context of the application process with full privileges.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-94/",
	"languages": ["node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["code-injection", "eval", "dynamic-execution", "cwe-94"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# JavaScript / TypeScript dangerous eval-like sinks
_js_eval_patterns := {
	"eval(",
	"new Function(",
	"Function(",
	"setTimeout(",
	"setInterval(",
	"execScript(",
}

# Python dynamic execution functions
_python_exec_patterns := {
	"eval(",
	"exec(",
	"compile(",
	"execfile(",
	"__import__(",
}

# PHP code execution
_php_exec_patterns := {
	"eval(",
	"assert(",
	"preg_replace(",
	"create_function(",
	"call_user_func(",
	"call_user_func_array(",
}

# Ruby dynamic evaluation
_ruby_eval_patterns := {
	"eval(",
	"instance_eval(",
	"class_eval(",
	"module_eval(",
	"binding.eval(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_js_ts(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _js_eval_patterns
	contains(line, pattern)
	_has_dynamic_content(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("JavaScript code injection risk: '%s' called with dynamic content; never pass user-controlled strings to eval or Function constructors", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# setTimeout/setInterval are only dangerous when the first arg is a string
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_js_ts(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "setTimeout(")
	# String argument (not a function reference)
	_has_string_argument(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": "setTimeout() called with a string argument; pass a function reference instead to prevent code injection",
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
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_exec_patterns
	contains(line, pattern)
	_has_user_controlled_variable(line)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python code injection: '%s' with user-controlled input executes arbitrary code; avoid dynamic evaluation of user data entirely", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python eval/exec bare — flag all uses as high-risk
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in {"eval(", "exec("}
	contains(line, pattern)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python '%s' is dangerous regardless of input source; review carefully and replace with a safe alternative (ast.literal_eval for data parsing)", [pattern]),
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _php_exec_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP code injection: '%s' is dangerous and can execute arbitrary code; avoid dynamic code evaluation and use safer alternatives", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# PHP preg_replace with /e modifier
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "preg_replace(")
	contains(line, "/e")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": "PHP preg_replace() with /e modifier evaluates the replacement as PHP code; use preg_replace_callback() instead",
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
	some pattern in _ruby_eval_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Ruby code injection: '%s' executes arbitrary code; avoid eval-style methods with external input", [pattern]),
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

_has_dynamic_content(line) if contains(line, "`")
_has_dynamic_content(line) if contains(line, "+ ")
_has_dynamic_content(line) if contains(line, "${")
_has_dynamic_content(line) if contains(line, "req.")
_has_dynamic_content(line) if contains(line, "request.")
_has_dynamic_content(line) if contains(line, "input")
_has_dynamic_content(line) if contains(line, "params")
_has_dynamic_content(line) if contains(line, "body")

_has_string_argument(line) if {
	# setTimeout("...", n) — string literal arg
	contains(line, "\"")
}
_has_string_argument(line) if contains(line, "'")

_has_user_controlled_variable(line) if contains(line, "input")
_has_user_controlled_variable(line) if contains(line, "request")
_has_user_controlled_variable(line) if contains(line, "req.")
_has_user_controlled_variable(line) if contains(line, "args")
_has_user_controlled_variable(line) if contains(line, "params")
_has_user_controlled_variable(line) if contains(line, "data")
_has_user_controlled_variable(line) if contains(line, "user")
_has_user_controlled_variable(line) if contains(line, "stdin")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
