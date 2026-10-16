# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_554

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-554",
	"name": "ASP.NET Misconfiguration: Not Using Input Validation Framework",
	"description": "ASP.NET request validation, the framework's built-in rejection of markup and script in request input, is switched off. Reported: a <%@ Page %> directive with ValidateRequest=\"false\" (in .aspx and .master files, also when the directive spans lines); <pages validateRequest=\"false\"> and <httpRuntime requestValidationMode=\"2.0\"> in Web.config and other .config files (the second confines validation to pages only, and is what makes validateRequest=\"false\" take effect on .NET 4+); and the MVC [ValidateInput(false)] attribute on an action or controller in C# or <ValidateInput(False)> in VB.NET. Not reported: validation left on or set to true, requestValidationMode 4.0/4.5, per-property [AllowHtml] and Request.Unvalidated (deliberate field-level opt-outs), ASP.NET Core (which has no request validation), XML and server-side comments (<!-- -->, <%-- --%>, including multi-line blocks), C# comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-554/",
	"languages": ["csharp", "xml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [554],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["aspnet", "request-validation", "cwe-554"],
}

_page_file(path) if {
	some ext in {".aspx", ".master"}
	endswith(lower(path), ext)
}

_config_file(path) if endswith(lower(path), ".config")

_code_file(path) if endswith(lower(path), ".cs")

_code_file(path) if endswith(lower(path), ".vb")

# Inside an XML/server comment opened above line i (or earlier on line i)
# and not closed before the match.
_in_comment(lines, i, line, open, close) if {
	before := concat("\n", array.slice(lines, 0, i))
	count(indexof_n(before, open)) > count(indexof_n(before, close))
}

_in_comment(_, _, line, open, close) if {
	k := indexof(line, open)
	k >= 0
	rest := substring(line, k, -1)
	not contains(rest, close)
}

_in_comment(_, _, line, open, close) if {
	k := indexof(line, open)
	k >= 0
	m := regex.find_all_string_submatch_n(`(?i)validateRequest|requestValidationMode`, line, 1)
	count(m) > 0
	j := indexof(lower(line), lower(m[0][0]))
	j > k
	e := indexof(line, close)
	e > j
}

# Page directive.
findings contains finding if {
	some path, content in input.file_contents
	_page_file(path)
	regex.match(`(?i)validateRequest\s*=\s*["']?false`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)\bvalidateRequest\s*=\s*["']?false\b`, line)
	_in_page_directive(lines, i)
	not _in_comment(lines, i, line, "<%--", "--%>")
	finding := _finding(path, i, line, "ValidateRequest=\"false\" turns off ASP.NET request validation for this page; leave it on and encode output instead")
}

_in_page_directive(lines, i) if {
	some k in numbers.range(max([0, i - 12]), i)
	regex.match(`(?i)<%@\s*(Page|Master)\b`, lines[k])
	not _directive_closed(lines, k, i)
}

_directive_closed(lines, k, i) if {
	k < i
	some m in numbers.range(k, i - 1)
	contains(lines[m], "%>")
}

# Web.config.
_config_re := `(?i)<pages\b[^>]*\bvalidateRequest\s*=\s*["']false["']|<httpRuntime\b[^>]*\brequestValidationMode\s*=\s*["']2\.0["']`

_config_attr_re := `(?i)\b(?:validateRequest\s*=\s*["']false["']|requestValidationMode\s*=\s*["']2\.0["'])`

# The attribute belongs to a <pages> or <httpRuntime> element opened on this
# line or up to six lines above (attributes are often one per line).
_config_element(lines, i) if regex.match(_config_re, lines[i])

_config_element(lines, i) if {
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(`(?i)<(?:pages|httpRuntime)\b`, lines[k])
	joined := concat("\n", array.slice(lines, k, i + 1))
	regex.match(`(?i)<(?:pages\b[^>]*\bvalidateRequest\s*=\s*["']false["']|httpRuntime\b[^>]*\brequestValidationMode\s*=\s*["']2\.0["'])`, joined)
}

findings contains finding if {
	some path, content in input.file_contents
	_config_file(path)
	regex.match(_config_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_config_attr_re, line)
	_config_element(lines, i)
	not _in_comment(lines, i, line, "<!--", "-->")
	finding := _finding(path, i, line, "Web.config switches ASP.NET request validation off (validateRequest=\"false\" or requestValidationMode=\"2.0\"); remove the setting")
}

# MVC attribute.
_attr_re := `(?i)[\[<,]\s*(?:System\.Web\.Mvc\.)?ValidateInput(?:Attribute)?\s*\(\s*(?:enableValidation\s*:=?\s*)?false\s*\)`

_strip(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	_code_file(path)
	contains(lower(content), "validateinput")
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "validateinput")
	not helpers.is_comment_line(line)
	not startswith(trim_space(line), "'")
	regex.match(_attr_re, _strip(line))
	finding := _finding(path, i, line, "[ValidateInput(false)] turns off ASP.NET request validation for this action; remove it, or allow markup on one field with [AllowHtml] and sanitise it")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
