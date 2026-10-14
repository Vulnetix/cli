package vulnetix.rules.vnx_html_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-HTML-001",
	"name": "Use of Jinja2 |safe filter",
	"description": "A Jinja2, Django or Nunjucks template switches off auto-escaping for a value: an output expression {{ ... }} whose filter chain applies safe or safeseq ({{ user.bio|safe }}, {{ c.body | safe }}, {{- post.content|markdown|safe -}}), or an {% autoescape off %} / {% autoescape false %} block. If the value can carry user-controlled data, it is rendered as raw HTML (XSS). Checked in .html, .htm, .jinja, .jinja2, .j2, .njk and .djhtml files. Not reported: a string literal marked safe, a value already escaped or JSON-encoded earlier in the chain (|escape|safe, |e|safe, |tojson|safe, |json_script), CSRF tokens and rendered form fields (csrf_token, form.x, field(...)), other filters whose name starts with safe, |safe in prose or script text outside {{ }}, Jinja {# #} comments, and templates under test directories. Twig |raw and Handlebars {{{ }}} are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-html-001/",
	"languages": ["html"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xss", "template", "jinja2", "safe"],
}

_is_template_file(path) if regex.match(`\.(html|htm|jinja|jinja2|j2|njk|djhtml)$`, path)

# `{{ <expr>|...|safe }}`: group 1 is everything before the safe filter.
_safe_expr := `\{\{-?\s*([^{}]*?)\|\s*(safe|safeseq)\s*(-?\}\}|\|)`

_autoescape_off := `\{%-?\s*autoescape\s+(off|false)\b`

# Already escaped or encoded before it is marked safe.
_escaped(expr) if regex.match(`\|\s*(e|escape|forceescape|tojson|json_script|escapejs|urlencode)\b`, expr)

# A literal is the template author's own markup.
_escaped(expr) if regex.match(`^\s*["']`, expr)

# CSRF tokens and rendered form fields are framework-produced markup.
_escaped(expr) if regex.match(`^\s*(csrf_token|csrf_input|form|field|wtf)\b`, expr)

# Cheap substring gates before any regular expression runs on the file.
_maybe(content) if contains(content, "safe")

_maybe(content) if contains(content, "autoescape")

_strip_comments(line) := regex.replace(line, `\{#.*?#\}`, "")

findings contains finding if {
	some path, content in input.file_contents
	_is_template_file(path)
	_maybe(content)
	not helpers.is_test_path(path)
	regex.match(`\|\s*safe|autoescape\s+(off|false)`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`\|\s*safe|autoescape`, raw)
	line := _strip_comments(raw)
	_unsafe(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Template output bypasses auto-escaping (|safe or autoescape off); if the value can contain user input this is XSS. Escape it, or sanitise the HTML before marking it safe",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

_unsafe(line) if regex.match(_autoescape_off, line)

_unsafe(line) if {
	some m in regex.find_all_string_submatch_n(_safe_expr, line, -1)
	not _escaped(m[1])
}
