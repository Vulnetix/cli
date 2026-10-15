# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_451

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-451",
	"name": "UI misrepresentation: hidden bidi controls in code, or a link that shows a different host",
	"description": "Reports two concrete ways the text a person reads differs from what the machine acts on. First, a Unicode bidirectional override or isolate control (U+202A-U+202E, U+2066-U+2069) written literally in a source-code file (Trojan Source, CVE-2021-42574): the editor and the review diff display the line reordered, so a comment or string appears to end where it does not and reviewers approve logic they cannot see. Second, an HTML/template anchor that misrepresents its destination: link text that reads as a URL (a scheme, www. or host/path) for a host unrelated to the constant href's host, or an href whose userinfo before '@' is itself a host name (https://bank.example@203.0.113.9/) so the real host is hidden. Not reported: escaped forms (\\u202e) in sanitisers, literal controls only inside a regex character-class range ([LRE-RLO]) that strips them, bidi marks in locale/data files (JSON, PO, YAML, XML), link text for the same host, a subdomain or parent domain, an href that contains the displayed host (archive links), dynamic hrefs or link text, plain-word link text, links split over several lines, and HTML comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-451/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [451],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["ui-misrepresentation", "trojan-source", "phishing", "comments", "cwe-451"],
}

_code_ext := `\.(?:go|py|pyw|js|mjs|cjs|jsx|ts|tsx|java|kt|kts|scala|groovy|c|h|cc|cpp|cxx|hpp|hh|cs|rb|php|rs|swift|m|mm|sh|bash|zsh|ps1|lua|pl|pm|dart|sql|tf|vue|svelte|ex|exs|erl|hs|clj)$`

_bidi := `[\x{202A}-\x{202E}\x{2066}-\x{2069}]`

_markup_ext := `\.(?:html?|xhtml|vue|svelte|jsx|tsx|php|erb|ejs|hbs|handlebars|mustache|jinja2?|j2|twig|jsp|cshtml|razor|liquid|njk|tmpl|gohtml)$`

_anchor := `<a\b[^>]*?\bhref\s*=\s*["'](https?://[^"'\s<>]+)["'][^>]*>([^<]*)</a\s*>`

# A file can only match when some anchor has userinfo in its href or link text
# that starts like an address.
_markup_gate := `<a\b[^>]*?\bhref\s*=\s*["']https?://(?:[^/"'@\s<>]+@|[^"'\s<>]+["'][^>]*>\s*(?:https?://|www\.|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/))`

_userinfo :=`<a\b[^>]*?\bhref\s*=\s*["']https?://([^/"'@\s<>]+)@([^/"'\s<>:]+)`

# The control characters themselves, built from their escapes so this file
# carries none of them: a plain substring test is far cheaper than a Unicode
# class regex over every source file.
_bidi_chars := {json.unmarshal(concat("", ["\"\\", "u", h, "\""])) |
	some h in ["202a", "202b", "202c", "202d", "202e", "2066", "2067", "2068", "2069"]
}

# A regex character class holding a range of the controls ([LRE-RLO]) is a
# sanitiser that strips them, not hidden reordering.
_bidi_range_class := `\[[^\]]*[\x{202A}-\x{202E}\x{2066}-\x{2069}]-[\x{202A}-\x{202E}\x{2066}-\x{2069}][^\]]*\]`

_has_bidi(content) if {
	some c in _bidi_chars
	contains(content, c)
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_code_ext, path)
	_has_bidi(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_bidi, line)
	regex.match(_bidi, regex.replace(line, _bidi_range_class, ""))
	finding := {
		"rule_id": metadata.id,
		"message": "A Unicode bidirectional control character is written literally in source code: editors and diffs display this line reordered, so what reviewers read is not what runs (Trojan Source). Remove it, or write it as an escape sequence",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The host a URL-looking text or href names, lower-cased, without www. or port.
_host(s) := h if {
	m := regex.find_all_string_submatch_n(`^\s*(?:https?://)?(?:[^/@\s]*@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)`, s, 1)
	h := trim_prefix(lower(m[0][1]), "www.")
}

# Link text that reads as an address: a scheme, a www. prefix, or host/path.
_url_text(t) if regex.match(`^\s*(?:https?://|www\.)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`, t)

_url_text(t) if regex.match(`^\s*[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/\S*\s*$`, t)

_related(a, b) if a == b

_related(a, b) if endswith(a, concat("", [".", b]))

_related(a, b) if endswith(b, concat("", [".", a]))

_misleading_text(href, text) if {
	not contains(text, "{")
	_url_text(text)
	shown := _host(text)
	real := _host(href)
	not _related(shown, real)
	not contains(lower(href), shown)
}

_markup_hit(line) := "text" if {
	some m in regex.find_all_string_submatch_n(_anchor, line, -1)
	_misleading_text(m[1], m[2])
}

_markup_hit(line) := "userinfo" if {
	not _markup_text(line)
	some m in regex.find_all_string_submatch_n(_userinfo, line, -1)
	regex.match(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?$`, m[1])
}

_markup_text(line) if {
	some m in regex.find_all_string_submatch_n(_anchor, line, -1)
	_misleading_text(m[1], m[2])
}

_link_message("text") := "The link text shows one address but the link goes to an unrelated host: users trust the destination they read. Make the visible text match the href"

_link_message("userinfo") := "The link's userinfo (before '@') is a host name, so the address reads as one site while the browser connects to the host after '@'. Remove the userinfo"

findings contains finding if {
	some path, content in input.file_contents
	regex.match(_markup_ext, path)
	contains(content, "href")
	regex.match(_markup_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "href")
	not startswith(trim_space(line), "<!--")
	not helpers.is_comment_line(line)
	kind := _markup_hit(line)
	finding := {
		"rule_id": metadata.id,
		"message": _link_message(kind),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
