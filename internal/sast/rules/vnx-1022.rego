# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1022",
	"name": "New window opened to an untrusted target with window.opener access (tabnabbing)",
	"description": "A page opens another document in a new browsing context that keeps a window.opener reference back to it, so the opened page can navigate the opener to a phishing copy (reverse tabnabbing). Reported: an <a>, <area>, <form>, React/Next <Link> or <NavLink> with target=\"_blank\" whose href (or form action) is dynamic (JSX {expr}, Vue :href/v-bind:href, Angular [href]/[attr.href], Thymeleaf th:href,, or a value that starts with a template expression {{ }}, <%= %>, <?= ?>, ${ } or Razor @) and no rel containing noopener or noreferrer; any such tag with rel=\"opener\"; and window.open(url, ...) with a non-constant URL, no noopener/noreferrer in its features and no .opener = null on the result. Not reported: links and window.open calls with a fixed URL or a fixed host and an interpolated path (current browsers apply noopener to target=_blank anchors by default, and a fixed link names a site the author chose), relative and same-page links and template route helpers ({{ url_for(...) }}, {{ path(...) }}, {% url %}, *_path, Hugo .Permalink/.RelPermalink/relURL, Jekyll site.baseurl), window.open to a template literal or concatenation that starts with a fixed host or a relative path, window.open to '_self'/'_parent'/'_top', comments, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1022/",
	"languages": ["html", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1022],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["target-blank", "tabnabbing", "window-opener", "cwe-1022"],
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

_markup(path) if regex.match(`\.(?:html?|xhtml|jsx|tsx|vue|svelte|astro|erb|ejs|jsp|jspx|php|phtml|twig|tpl|hbs|mustache|cshtml|razor|gohtml|tmpl|njk|liquid|js|ts)$`, path)

_script(path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|vue|svelte|astro|html?|ejs|erb|php|jsp|cshtml|razor|hbs|twig)$`, path)

_blank_re := `target\s*=\s*\{?\s*["'\x60]_blank["'\x60]`

# The URL itself (scheme and host) comes from an expression: the value starts
# with one. A fixed host with an interpolated path or query names a site the
# author chose, and a relative URL stays on this origin.
_dynamic_href := `(?i)(?:^|\s)(?:href|action)\s*=\s*\{\s*(?:[^"'\s\x60]|\x60\s*\$\{)|(?:^|\s)(?::|v-bind:)(?:href|action)\s*=\s*["']\s*[^'"\s]|\[(?:attr\.)?(?:href|action)\]\s*=\s*["']\s*[^'"\s]|th:(?:href|action)\s*=\s*["']\s*(?:\$\{|\*\{|@\{\s*\$\{)|(?:^|\s)(?:href|action)\s*=\s*["']\s*(?:\{\{|<%=?|<\?(?:=|php)|\$\{|@[A-Za-z(])`

# Template helpers that build a same-origin route.
_route_href := `(?i)(?:^|\s)(?:href|action)\s*=\s*["']\s*(?:\{\{\s*(?:url_for\b|(?:url|route|path|asset|static)\s*\(|(?:relURL|absURL|relLangURL|absLangURL)\b|\.(?:RelPermalink|Permalink|Site\.BaseURL)\b|(?:site|page)\.(?:baseurl|url)\b)|<%=?\s*\w+_path\b)`

_rel_safe := `(?i)\brel\s*=\s*\{?\s*["'\x60][^"'\x60]*\bno(?:opener|referrer)\b`

_rel_opener := `(?i)\brel\s*=\s*\{?\s*["'\x60](?:[^"'\x60]*\s)?opener(?:\s[^"'\x60]*)?["'\x60]`

# Index of the nearest line at or above i (within 8) that opens the tag.
_opener(lines, i) := j if {
	js := [k |
		some d in numbers.range(0, min([i, 8]))
		k := i - d
		regex.match(`<(?:a|area|form|Link|NavLink)\b`, lines[k])
	]
	count(js) > 0
	j := js[0]
}

# The opening tag (through its closing ">", ignoring "=>") that contains the
# target="_blank" on line i.
_tag(lines, i) := t if {
	j := _opener(lines, i)
	txt := concat("\n", [lines[k] | some k in numbers.range(j, min([count(lines) - 1, i + 6]))])
	tags := [m[0] |
		some m in regex.find_all_string_submatch_n(`(?s)<(?:a|area|form|Link|NavLink)\b(?:=>|\?>|%>|[^>])*>`, txt, -1)
		regex.match(_blank_re, m[0])
	]
	count(tags) > 0
	t := tags[0]
}

findings contains _finding(path, i, line, "target=\"_blank\" link to a dynamic URL without rel=\"noopener noreferrer\": the opened page gets window.opener and can redirect this tab to a phishing page. Add rel=\"noopener noreferrer\"") if {
	some path, content in input.file_contents
	_markup(path)
	not helpers.is_test_path(path)
	contains(content, "_blank")
	regex.match(`(?i)(?:href|action)\s*=\s*(?:\{|["']\s*(?:\{\{|<%|<\?|\$\{|@))|:(?:href|action)\s*=|\[(?:attr\.)?(?:href|action)\]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_blank_re, line)
	not regex.match(`^\s*(?://|<!--|\*|#)`, line)
	tag := _tag(lines, i)
	not regex.match(_rel_safe, tag)
	not regex.match(_rel_opener, tag)
	regex.match(_dynamic_href, tag)
	not regex.match(_route_href, tag)
}

findings contains _finding(path, i, line, "target=\"_blank\" link with rel=\"opener\": the opened page is deliberately given window.opener and can redirect this tab to a phishing page. Use rel=\"noopener noreferrer\"") if {
	some path, content in input.file_contents
	_markup(path)
	not helpers.is_test_path(path)
	contains(content, "_blank")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_blank_re, line)
	not regex.match(`^\s*(?://|<!--|\*|#)`, line)
	tag := _tag(lines, i)
	regex.match(_rel_opener, tag)
}

findings contains _finding(path, i, line, "window.open() to a variable or external URL without noopener: the new window gets window.opener and can redirect this tab to a phishing page. Pass 'noopener,noreferrer' as the features or set the result's opener to null") if {
	some path, content in input.file_contents
	_script(path)
	not helpers.is_test_path(path)
	contains(content, "window.open(")
	lines := split(content, "\n")
	some i, line in lines
	idx := indexof(line, "window.open(")
	idx >= 0
	not helpers.is_comment_line(line)
	contains(_strip(line), "window.open(")
	call :=concat("\n", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 3]))])
	args := substring(call, idx + 12, -1)
	_untrusted_url(args)
	not regex.match(`(?i)noopener|noreferrer`, call)
	not regex.match(`^\s*[^,]+,\s*["'\x60]_(?:self|parent|top)["'\x60]`, args)
	not _opener_nulled(lines, i)
}

# A variable, expression or template, or an absolute external URL literal.
_untrusted_url(args) if regex.match(`^\s*[A-Za-z_$(\[]`, args)

_untrusted_url(args) if regex.match(`^\s*\x60\s*(?:(?:https?:)?//)?\$\{`, args)

_untrusted_url(args) if regex.match(`^\s*["'](?:https?:)?(?://)?["']\s*\+`, args)

_opener_nulled(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 3]))
	regex.match(`\.opener\s*=\s*null`, lines[k])
}

_strip(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)
