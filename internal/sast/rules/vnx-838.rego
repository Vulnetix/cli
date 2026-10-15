# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_838

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-838",
	"name": "Inappropriate Encoding for Output Context",
	"description": "A value encoded for one output context is written into another. JavaScript/TypeScript: URL encoding (encodeURIComponent, encodeURI, the global escape) used for text written to an HTML sink (innerHTML/outerHTML assignment, insertAdjacentHTML, document.write, jQuery .html(), dangerouslySetInnerHTML); URL encoding leaves ' unescaped and is not HTML encoding, so the markup is still injectable. Python: urllib.parse.quote/quote_plus used inside HTML markup (a string with a tag, or Markup()/mark_safe()), and html.escape(..., quote=False) or cgi.escape() (which does not escape quotes by default) used inside an HTML attribute value, where the attacker closes the quote. The encoder must sit inside what the sink writes (after innerHTML =, inside .html(...)); for a Python format operation ('...%s...' % quote(x), '...{}...'.format(...)) the first argument is judged at the template's first placeholder. Not reported: a URL-encoded request URL on the same line as an unrelated sink, URL encoding of a value placed in a URL attribute (href, src, action, formaction, poster, cite, data, background), URL encoding for a URL or textContent, HTML escapers (escapeHtml, _.escape, html.escape with quotes), html.escape(quote=False) in element text, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-838/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [838],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inappropriate-encoding-for-output-context", "xss", "output-encoding", "cwe-838"],
}

_js_ext := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_is_js(path) if {
	some ext in _js_ext
	endswith(path, ext)
}

# Quoted strings blanked (template literals kept: their ${...} is code).
_strip_quotes(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'", "\"\"")

_js_sink_re := `\.(?:innerHTML|outerHTML)\s*\+?=|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\.html\s*\(|\bdangerouslySetInnerHTML\b`

_js_enc_re := `^(.*?)(?:\bencodeURIComponent|\bencodeURI|(?:^|[^\w.$])escape)\s*\(`

_py_quote_re := `^(.*?)(?:^|[^\w.])(?:urllib\.parse\.|parse\.|urllib\.)?quote(?:_plus)?\s*\(`

_py_attr_esc_re := `^(.*?)(?:\bhtml\.escape\s*\([^)]*\bquote\s*=\s*False|\bcgi\.escape\s*\((?:[^)]*\bquote\s*=\s*False)?[^)]*\))`

# The text after the last '<' of the prefix: the tag being built, if any.
_tag_tail(prefix) := t if {
	parts := split(prefix, "<")
	count(parts) > 1
	t := parts[count(parts) - 1]
}

# The value lands in a URL attribute of the tag being built.
_in_url_attr(prefix) if {
	t := _tag_tail(prefix)
	not contains(t, ">")
	regex.match(`(?i)\b(?:href|src|action|formaction|poster|cite|data|background|srcset)\s*=`, t)
}

# The value lands inside an attribute value of the tag being built.
_in_attr_value(prefix) if {
	t := _tag_tail(prefix)
	not contains(t, ">")
	regex.match(`=\s*\\?["']`, t)
}

# When the encoder is the first argument of a format operation
# ('<a href="/s?q=%s">' % quote(q), '<b title="{}">'.format(...)), the value
# lands at the template's first placeholder: judge the text before it.
_fmt_prefix(prefix) := m[0][1] if {
	regex.match(`(?:%\s*\(?|\.format\s*\(?)\s*$`, prefix)
	m := regex.find_all_string_submatch_n(`^(.*?)(?:%[sr]|\{\d?\})`, prefix, 1)
	count(m) > 0
}

_ctx_prefix(prefix) := _fmt_prefix(prefix)

_ctx_prefix(prefix) := prefix if not _fmt_prefix(prefix)

_markup_context(prefix) if regex.match(`<[A-Za-z]`, prefix)

_markup_context(prefix) if regex.match(`\b(?:Markup|mark_safe)\s*\(`, prefix)

_report(path, line) := "URL encoding (encodeURIComponent/encodeURI/escape) used for a value written into HTML: it is not HTML encoding and leaves quotes and markup injectable. Use textContent or an HTML escaper" if {
	_is_js(path)
	regex.match(_js_sink_re, _strip_quotes(line))
	m := regex.find_all_string_submatch_n(_js_enc_re, line, 1)
	count(m) > 0
	regex.match(_js_sink_re, _strip_quotes(m[0][1]))
	not _in_url_attr(_ctx_prefix(m[0][1]))
}

_report(path, line) := "URL quoting (urllib.parse.quote) used for text placed in HTML markup: it is not HTML escaping. Use html.escape or the template engine's autoescaping" if {
	endswith(path, ".py")
	contains(line, "quote")
	m := regex.find_all_string_submatch_n(_py_quote_re, line, 1)
	count(m) > 0
	_markup_context(m[0][1])
	not _in_url_attr(_ctx_prefix(m[0][1]))
}

_report(path, line) := "HTML escaping without quote escaping (html.escape(quote=False) / cgi.escape) used inside an attribute value: a quote in the input closes the attribute. Use html.escape(value) with quote=True" if {
	endswith(path, ".py")
	contains(line, "escape")
	m := regex.find_all_string_submatch_n(_py_attr_esc_re, line, 1)
	count(m) > 0
	_in_attr_value(_ctx_prefix(m[0][1]))
}

# Whole-file gates per language, so most files are never split.
_candidate(path, content) if {
	_is_js(path)
	not regex.match(`[.-]min\.js$`, path)
	contains(content, "HTML")
	regex.match(`encodeURI|[^\w.$]escape\s*\(`, content)
}

_candidate(path, content) if {
	_is_js(path)
	not regex.match(`[.-]min\.js$`, path)
	regex.match(`\.html\s*\(|document\.write`, content)
	regex.match(`encodeURI|[^\w.$]escape\s*\(`, content)
}

_candidate(path, content) if {
	endswith(path, ".py")
	contains(content, "quote")
	contains(content, "urllib")
	contains(content, "<")
}

_candidate(path, content) if {
	endswith(path, ".py")
	regex.match(`cgi\.escape|quote\s*=\s*False`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_candidate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`encodeURI|escape|quote`, line)
	count(line) < 500
	not helpers.is_comment_line(line)
	msg := _report(path, line)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
