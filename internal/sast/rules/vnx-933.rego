# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_933

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-933",
	"name": "Script loaded over plain HTTP",
	"description": "CWE-933 is the OWASP Top Ten 2013 Security Misconfiguration category with no code shape of its own; this rule reports the concrete misconfiguration it was generated for, a page that loads executable script over plain http://, which anyone on the network path can replace with their own code. Reported: a <script> tag whose src is an http:// URL in HTML and server-side template files (.html, .htm, .php, .jsp, .erb, .ejs, .cshtml, .aspx, .vue, .svelte, .jsx, .tsx, Jinja, Twig, Handlebars and similar), with any quoting or letter case and with the src attribute on a later line of the start tag; and in JavaScript/TypeScript, an element made by document.createElement(\"script\") whose src is set to an http:// URL a few lines later (el.src = or el.setAttribute(\"src\", ...)), and $.getScript/jQuery.getScript or a worker's importScripts called with an http:// URL. Not reported: https:// and protocol-relative or relative src values, loopback development servers (localhost, 127.0.0.1, 0.0.0.0, [::1]), http:// URLs on links, images or inside inline script code, HTML comments (single-line or multi-line), test files, and script URLs assembled at run time. A tag with an integrity attribute is still reported: on an HTTPS page the browser blocks the script as mixed content, and on an HTTP page the attacker can rewrite the tag itself.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-933/",
	"languages": ["html", "javascript", "typescript", "php", "java", "csharp", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [933],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cross-origin-script-inclusion", "cwe-933"],
}

_markup_exts := {
	".html", ".htm", ".xhtml", ".shtml", ".php", ".phtml", ".jsp", ".jspx", ".erb", ".ejs",
	".cshtml", ".vbhtml", ".razor", ".aspx", ".ascx", ".master", ".hbs", ".handlebars",
	".mustache", ".twig", ".jinja", ".jinja2", ".j2", ".njk", ".liquid", ".tpl", ".vue",
	".svelte", ".gohtml", ".tmpl", ".jsx", ".tsx",
}

# Line i sits inside a multi-line <!-- ... --> comment opened above (bounded).
_in_html_comment(lines, i) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "<!--")
	parts := split(lines[j], "<!--")
	not contains(parts[count(parts) - 1], "-->")
	every k in helpers.span(j + 1, i - 1) {
		not contains(lines[k], "-->")
	}
	not regex.match(`-->.*<script`, lower(lines[i]))
}

_js_exts := {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".html", ".htm"}

_markup(path) if {
	some e in _markup_exts
	endswith(lower(path), e)
}

_js(path) if {
	some e in _js_exts
	endswith(lower(path), e)
}

_skip(path) if endswith(path, ".min.js")

_skip(path) if helpers.is_test_path(path)

_loopback(host) if regex.match(`^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])$`, lower(host))

# --- <script src="http://..."> in markup -------------------------------------

_src_http := `(?i)\bsrc\s*=\s*["']?http://(\[[^\]]*\]|[^/"'\s>:?#]+)`

_in_script_tag(line, _, _) if regex.match(`(?i)<script\b[^>]*\bsrc\s*=\s*["']?http://`, line)

# The start tag opened on an earlier line and is still open on this one.
_in_script_tag(line, lines, i) if {
	regex.match(`(?i)^[^<>]*\bsrc\s*=\s*["']?http://`, line)
	some j in numbers.range(max([0, i - 5]), i - 1)
	regex.match(`(?i)<script\b[^>]*$`, lines[j])
	every k in helpers.span(j + 1, i - 1) {
		not contains(lines[k], ">")
		not contains(lines[k], "<")
	}
}

_markup_hit(line, lines, i) := host if {
	m := regex.find_all_string_submatch_n(_src_http, line, 1)
	count(m) > 0
	host := m[0][1]
	not _loopback(host)
	not startswith(trim_space(line), "<!--")
	_in_script_tag(line, lines, i)
	not _in_html_comment(lines, i)
}

# --- document.createElement("script") with an http:// src -------------------

_js_set := `(?i)\b([A-Za-z_$][\w$]*)\s*(\.\s*src\s*=\s*|\.\s*setAttribute\s*\(\s*["']src["']\s*,\s*)["'\x60]http://(\[[^\]]*\]|[^/"'\x60\s:?#]+)`

_js_hit(line, lines, i) := host if {
	m := regex.find_all_string_submatch_n(_js_set, line, 1)
	count(m) > 0
	v := m[0][1]
	host := m[0][3]
	not _loopback(host)
	not helpers.is_comment_line(line)
	some j in numbers.range(max([0, i - 8]), i)
	regex.match(concat("", [`\b`, v, `(\s*:\s*[\w.<>|]+)?\s*=\s*(window\.)?document\s*\.\s*createElement\s*\(\s*["'\x60]script["'\x60]`]), lines[j])
}

# jQuery.getScript / $.getScript and a worker's importScripts fetch and run the script.
_loader_re := `(?i)((\$|\bjQuery)\s*\.\s*getScript|\bimportScripts)\s*\(\s*["'\x60]http://(\[[^\]]*\]|[^/"'\x60\s:?#]+)`

_js_hit(line, _, _) := host if {
	m := regex.find_all_string_submatch_n(_loader_re, line, 1)
	count(m) > 0
	host := m[0][3]
	not _loopback(host)
	not helpers.is_comment_line(line)
}

_finding(path, i, line, host) := {
	"rule_id": metadata.id,
	"message": sprintf("Script loaded over plain HTTP from %s: anyone on the network path can replace it with their own code. Serve it over https:// (with Subresource Integrity) or host it yourself", [host]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_markup(path)
	not _skip(path)
	regex.match(`(?i)<script\b`, content)
	regex.match(`(?i)\bsrc\s*=\s*["']?http://`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "http://")
	host := _markup_hit(line, lines, i)
	finding := _finding(path, i, line, host)
}

findings contains finding if {
	some path, content in input.file_contents
	_js(path)
	not _skip(path)
	regex.match(`createElement\s*\(\s*["'\x60]script|getScript\s*\(|importScripts\s*\(`, content)
	contains(lower(content), "http://")
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "http://")
	host := _js_hit(line, lines, i)
	finding := _finding(path, i, line, host)
}
