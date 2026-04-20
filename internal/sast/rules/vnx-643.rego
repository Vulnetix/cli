# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_643

import rego.v1

metadata := {
	"id": "VNX-643",
	"name": "XPath Injection",
	"description": "User-controlled data is concatenated directly into an XPath expression. An attacker can manipulate the XPath query to bypass authentication, extract arbitrary XML node values, or enumerate the full document structure.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-643/",
	"languages": ["java", "python", "node", "php", "ruby", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [643],
	"capec": ["CAPEC-83"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xpath", "injection", "xml", "cwe-643"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Java XPath evaluate/compile patterns
_java_xpath_patterns := {
	"xpath.evaluate(",
	"xpath.compile(",
	"XPath.evaluate(",
	"xPath.evaluate(",
	".evaluate(\"//",
	".evaluate('//",
}

# Python lxml / ElementTree xpath patterns
_python_xpath_patterns := {
	".xpath(f\"",
	".xpath(f'",
	".xpath(\"//",
	".xpath('//",
	".xpath(user",
	".xpath(request",
	".xpath(input",
	"findall(f\"",
	"findall(f'",
}

# Generic string concatenation with XPath-like fragments
_concat_xpath_patterns := {
	"//user[name='\" +",
	"//user[name=\"\" +",
	"//[@name='\" +",
	"//[@name=\"\" +",
	"XPathExpression",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_xpath_patterns
	contains(line, p)
	_has_concat_or_var(line)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java XPath operation '%s' appears to use dynamic input; use XPathVariableResolver or parameterised XPath queries to prevent XPath injection", [p]),
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
	some p in _python_xpath_patterns
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python XPath call '%s' with dynamic data; use lxml's XPath variable substitution (e.g. tree.xpath('//user[@name=$n]', n=name)) instead of string interpolation", [p]),
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _concat_xpath_patterns
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("XPath injection pattern '%s' detected; never concatenate user input into XPath expressions", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_concat_or_var(line) if contains(line, " + ")
_has_concat_or_var(line) if contains(line, "\"+")
_has_concat_or_var(line) if contains(line, "'+")
_has_concat_or_var(line) if contains(line, "request.")
_has_concat_or_var(line) if contains(line, "req.")
_has_concat_or_var(line) if contains(line, "getParameter(")
_has_concat_or_var(line) if contains(line, "userInput")
_has_concat_or_var(line) if contains(line, "user_input")
