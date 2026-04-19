# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_79

import rego.v1

metadata := {
	"id": "VNX-79",
	"name": "Cross-Site Scripting (XSS)",
	"description": "Unescaped user-controlled data is rendered in an HTML context. An attacker can inject malicious scripts that execute in the victim's browser, leading to session hijacking, credential theft, or malware delivery.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-79/",
	"languages": ["java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xss", "injection", "html", "cwe-79"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# JavaScript / React DOM XSS sinks
_js_dom_sinks := {
	"dangerouslySetInnerHTML",
	"innerHTML =",
	"innerHTML=",
	"outerHTML =",
	"outerHTML=",
	"document.write(",
	"document.writeln(",
	"insertAdjacentHTML(",
}

# PHP — direct echo of superglobals (no escaping function wrapping)
_php_echo_patterns := {
	"echo $_GET",
	"echo $_POST",
	"echo $_REQUEST",
	"echo $_COOKIE",
	"print $_GET",
	"print $_POST",
	"print $_REQUEST",
}

# Ruby on Rails — marking user content as safe
_ruby_html_safe_patterns := {
	".html_safe",
	"raw(",
	"html_safe(",
}

# Python Django — mark_safe / format_html misuse
_python_mark_safe_patterns := {
	"mark_safe(",
	"format_html(",
}

# Java — response writer printing request parameters
_java_xss_patterns := {
	"response.getWriter().print(",
	"response.getWriter().println(",
	"out.print(",
	"out.println(",
	"out.write(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_js_ts(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some sink in _js_dom_sinks
	contains(line, sink)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DOM XSS sink '%s' used; avoid setting raw HTML from user input. Use textContent/innerText or a sanitiser like DOMPurify", [sink]),
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
	some pattern in _php_echo_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP XSS: unescaped output '%s'; wrap with htmlspecialchars(..., ENT_QUOTES, 'UTF-8') before echoing user input", [pattern]),
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
	some pattern in _ruby_html_safe_patterns
	contains(line, pattern)
	# Only flag when user-controlled variables appear nearby
	_has_user_controlled_variable(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Ruby/Rails XSS: '%s' used with what appears to be user-controlled input; Rails auto-escapes ERB — avoid bypassing it with html_safe/raw", [pattern]),
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
	some pattern in _python_mark_safe_patterns
	contains(line, pattern)
	_has_user_controlled_variable(line)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Django XSS: '%s' called with user-controlled data; mark_safe bypasses auto-escaping. Use format_html() with safe format strings, or escape manually", [pattern]),
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _java_xss_patterns
	contains(line, pattern)
	_has_java_request_data(line)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java XSS: '%s' may print unescaped request data; use OWASP Java Encoder or StringEscapeUtils to escape before writing to the response", [pattern]),
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

_has_user_controlled_variable(line) if contains(line, "params")
_has_user_controlled_variable(line) if contains(line, "request")
_has_user_controlled_variable(line) if contains(line, "user_input")
_has_user_controlled_variable(line) if contains(line, "userInput")
_has_user_controlled_variable(line) if contains(line, "input")
_has_user_controlled_variable(line) if contains(line, "query")
_has_user_controlled_variable(line) if contains(line, "body")
_has_user_controlled_variable(line) if contains(line, "data")

_has_java_request_data(line) if contains(line, "getParameter(")
_has_java_request_data(line) if contains(line, "getHeader(")
_has_java_request_data(line) if contains(line, "getQueryString()")
_has_java_request_data(line) if contains(line, "request.")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
