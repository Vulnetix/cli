# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_78

import rego.v1

metadata := {
	"id": "VNX-78",
	"name": "OS Command Injection",
	"description": "User-controlled data is passed to a shell or process-execution function without sanitisation. An attacker can inject shell metacharacters to execute arbitrary commands on the host operating system.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-78/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["command-injection", "os-command", "cwe-78"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Python — shell=True is the critical flag; subprocess without it is much safer
_python_shell_true_patterns := {
	"subprocess.call(",
	"subprocess.run(",
	"subprocess.Popen(",
	"subprocess.check_output(",
	"subprocess.check_call(",
}

# Unconditionally dangerous shell-execution sinks
_unconditional_patterns := {
	# Python
	"os.system(",
	"os.popen(",
	# PHP
	"shell_exec(",
	"passthru(",
	"proc_open(",
	# Node.js
	"child_process.exec(",
	"child_process.execSync(",
	"require('child_process').exec(",
	"require(\"child_process\").exec(",
	# Java
	"Runtime.getRuntime().exec(",
	# Ruby
	"`",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _unconditional_patterns
	contains(line, pattern)
	not _is_comment(path, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Dangerous shell execution sink '%s' detected; avoid shell execution with user input, or use parameterised APIs and strict allowlists", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python subprocess with shell=True — dangerous only when shell=True is present
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_shell_true_patterns
	contains(line, pattern)
	contains(line, "shell=True")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' called with shell=True; this allows shell injection. Pass a list of arguments and omit shell=True", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js exec / execSync with template literal or string concatenation
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_js_ts(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "exec(")
	# Template literal or concatenation inside the call
	_has_dynamic_string(line)
	not _is_comment(path, line)
	finding := {
		"rule_id": metadata.id,
		"message": "exec() called with a dynamic string; use execFile() with an array of arguments and never interpolate user input into shell commands",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# PHP echo/print of exec output combined with user input
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "exec(")
	_has_php_user_input(line)
	finding := {
		"rule_id": metadata.id,
		"message": "PHP exec() called with user-controlled input; validate and escape all arguments, or avoid shell execution entirely",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Go exec.Command with string concatenation
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "exec.Command(")
	_has_dynamic_string(line)
	finding := {
		"rule_id": metadata.id,
		"message": "exec.Command() called with a dynamically constructed argument; pass each argument as a separate string to avoid shell injection",
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

_has_dynamic_string(line) if contains(line, "`")
_has_dynamic_string(line) if contains(line, "+ ")
_has_dynamic_string(line) if contains(line, " +")
_has_dynamic_string(line) if contains(line, "${")

_has_php_user_input(line) if contains(line, "$_GET")
_has_php_user_input(line) if contains(line, "$_POST")
_has_php_user_input(line) if contains(line, "$_REQUEST")
_has_php_user_input(line) if contains(line, "$_COOKIE")

_is_comment(path, line) if {
	endswith(path, ".py")
	startswith(trim_space(line), "#")
}
_is_comment(path, line) if {
	not endswith(path, ".py")
	startswith(trim_space(line), "//")
}
_is_comment(_, line) if startswith(trim_space(line), "*")
_is_comment(_, line) if startswith(trim_space(line), "/*")
