# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_357

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-357",
	"name": "Destructive link or button without a confirmation step",
	"description": "A link or button that issues a DELETE request in one click carries no confirmation, although the framework offers one on the same element, so a stray click or a click on a mis-rendered row destroys data without warning. Reported in Rails views and helpers (.erb, .haml, .slim, .rb): link_to / button_to with method: :delete (or :method => :delete, data: { turbo_method: :delete } or data: { \"turbo-method\": :delete }) whose call, followed across continuation lines, has no confirm:, data-confirm or turbo_confirm; and in HTML/templates (.html, .htm, .erb, .ejs, .hbs, .php, .twig, .jinja, .j2): an <a ... data-method=\"delete\"> (rails-ujs / jquery-ujs) or data-turbo-method=\"delete\" (Turbo) tag, read past ERB/PHP tags inside its attributes, with no data-confirm or data-turbo-confirm. Not reported: elements that ask for confirmation, GET/PATCH/POST links, sign-out links (a DELETE of the session: sign_out, logout, destroy_user_session_path, /session), prose, ERB and HTML comments, and buttons wired to a JavaScript handler (onclick=, (click)=, @click=), because whether that handler confirms is decided elsewhere.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-357/",
	"languages": ["ruby", "html"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [357],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["insufficient-dangerous-op-warning", "rails", "confirmation", "cwe-357"],
}

_rails_file(path) if regex.match(`\.(erb|haml|slim|rb)$`, path)

_html_file(path) if regex.match(`\.(html?|erb|ejs|hbs|handlebars|php|twig|jinja2?|j2|njk|mustache)$`, path)

_markup_comment(line) if regex.match(`^\s*(?:<!--|<%#|-#|/\s)`, line)

# Statement starting on line i, joined with continuation lines (a line ending
# in ",", "(" or "{"), at most five lines.
# A call whose parentheses close on its own line (an element of a list or
# argument array) ends there: the continuation belongs to the next element.
_closed_call(line) if {
	regex.match(`\b(?:link_to|button_to)\(`, line)
	count(split(line, "(")) == count(split(line, ")"))
}

_statement(lines, i) := lines[i] if _closed_call(lines[i])

_statement(lines, i) := concat("\n", array.slice(lines, i, i + n)) if {
	not _closed_call(lines[i])
	end := min([count(lines), i + 5])
	stops := [k |
		some k in numbers.range(i, end - 1)
		not regex.match(`[,(\{]\s*$`, lines[k])
	]
	n := _first_or(stops, end - 1) - i + 1
}

# The last <a tag opened on line i, up to its closing ">" within five lines.
_tag(lines, i) := first if {
	first := regex.replace(lines[i], `^.*(<a\b)`, "$1")
	contains(first, ">")
}

_tag(lines, i) := concat("\n", array.concat([first], array.slice(lines, i + 1, i + 1 + n))) if {
	first := regex.replace(lines[i], `^.*(<a\b)`, "$1")
	not contains(first, ">")
	end := min([count(lines), i + 5])
	stops := [k |
		some k in helpers.span(i + 1, end - 1)
		contains(lines[k], ">")
	]
	n := _first_or(stops, end - 1) - i
}

# The call is Ruby: a helper file, an ERB tag, or a HAML/Slim "=" / "-" line.
_ruby_ctx(path, _) if endswith(path, ".rb")

_ruby_ctx(_, line) if regex.match(`<%[=-]?[^%]*\b(?:link_to|button_to)\b`, line)

_ruby_ctx(path, line) if {
	regex.match(`\.(haml|slim)$`, path)
	regex.match(`^\s*(?:[%.#][\w.#-]*(?:\{[^}]*\})?)?\s*[=-]\s*(?:link_to|button_to)\b`, line)
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_rails_delete := `(?:method:\s*|:method\s*=>\s*|turbo_method:\s*|["']?(?:data-)?turbo-method["']?\s*(?::|=>)\s*)["':]?delete\b`

# Signing out is a DELETE of the session (Devise's destroy_user_session_path),
# not destruction of data, and is never confirmed.
_sign_out := `(?i)sign[_-]?out|log[_-]?out|log[_-]?off|sessions?_(?:path|url)\b|/sessions?\b`

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	_rails_file(path)
	contains(content, "delete")
	regex.match(`\b(?:link_to|button_to)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:link_to|button_to)\b`, line)
	_ruby_ctx(path, line)
	not helpers.is_comment_line(line)
	not _markup_comment(line)
	stmt := _statement(lines, i)
	regex.match(_rails_delete, stmt)
	not regex.match(`(?i)confirm`, stmt)
	not regex.match(_sign_out, stmt)
	finding := _finding(path, i, line, "A link_to/button_to that sends DELETE has no confirmation: one click destroys the record without warning. Add data: { turbo_confirm: \"...\" } (or confirm:/data-confirm for rails-ujs)")
}

findings contains finding if {
	some path, content in input.file_contents
	_html_file(path)
	regex.match(`data-(?:turbo-)?method\s*=\s*["']?delete`, content)
	# an ERB/EJS/PHP tag's closing "%>" or "?>" inside an attribute is not the anchor's ">"
	lines := split(regex.replace(content, `([%?])>`, "$1}"), "\n")
	raw := split(content, "\n")
	some i, eline in lines
	regex.match(`<a\b`, eline)
	not _markup_comment(eline)
	line := raw[i]
	tag := _tag(lines, i)
	regex.match(`^<a\b[^>]*data-(?:turbo-)?method\s*=\s*["']?delete\b`, tag)
	not regex.match(`(?i)data-(?:turbo-)?confirm`, tag)
	not regex.match(_sign_out, tag)
	not regex.match(`(?i)\s(?:onclick|\(click\)|@click|v-on:click|x-on:click|ng-click)\s*=`, tag)
	finding := _finding(path, i, line, "An anchor with data-method=\"delete\" has no data-confirm: one click destroys the resource without warning. Add data-confirm (rails-ujs) or data-turbo-confirm")
}
