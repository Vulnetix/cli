# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_353

import rego.v1

metadata := {
	"id": "VNX-353",
	"name": "Third-party script or stylesheet loaded without Subresource Integrity",
	"description": "An HTML page or server-side template loads JavaScript or CSS from another origin with no integrity check, so whoever controls that CDN (or the network path, for http://) can change the code the page runs. Reported: a <script> tag whose src, or a <link rel=\"stylesheet\"> whose href, is an absolute http(s):// or protocol-relative // URL and whose tag (which may span up to six lines) carries no integrity= attribute (every such tag on a line is checked), in .html/.htm/.xhtml and template files (ERB, EJS, Handlebars, Mustache, Jinja/Django/Nunjucks/Twig/Liquid, JSP, Razor, PHP, Vue/Svelte, Go templates). Not reported: tags with integrity= or a framework binding of it (:integrity, v-bind:integrity, [attr.integrity]), same-origin and relative URLs, development servers on localhost/127.0.0.1, a src built from a template expression, other <link> relations (canonical, preconnect, icon, alternate), anchors, HTML-escaped and commented-out tags, prose files, and endpoints that serve per-request content and cannot be pinned by a hash (Google Tag Manager/Analytics, reCAPTCHA, hCaptcha, Turnstile, Google Fonts CSS, Google Maps/APIs/Sign-In, Stripe.js, Font Awesome kits, Facebook/Twitter widgets).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-353/",
	"languages": ["html"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [353],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["integrity-check", "subresource-integrity", "supply-chain", "cwe-353"],
}

_template(path) if regex.match(`(?i)\.(?:html?|xhtml|erb|ejs|hbs|handlebars|mustache|jinja2?|j2|njk|twig|liquid|jspx?|cshtml|razor|php|phtml|vue|svelte|gohtml|tmpl|tpl)$`, path)

# Endpoints whose response varies per request or per browser: a hash cannot
# be pinned, and their vendors document that SRI is not supported.
_dynamic_hosts := `(?i)^(?:https?:)?//(?:www\.)?(?:googletagmanager\.com|google-analytics\.com|google\.com/recaptcha|gstatic\.com/recaptcha|recaptcha\.net|js\.hcaptcha\.com|hcaptcha\.com|challenges\.cloudflare\.com|fonts\.googleapis\.com|fonts\.bunny\.net|maps\.googleapis\.com|maps\.google\.com|apis\.google\.com|accounts\.google\.com|js\.stripe\.com|kit\.fontawesome\.com|connect\.facebook\.net|platform\.twitter\.com|static\.cloudflareinsights\.com)`

# A development server on this machine (Vite, webpack-dev-server) is not a third party.
_local_hosts := `(?i)^(?:https?:)?//(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])(?:[:/]|$)`

# The tag opened at column col of line i, up to its first '>' (at most six lines).
_tag(lines, i, col) := t if {
	end := min([count(lines) - 1, i + 5])
	joined := concat(" ", array.concat([substring(lines[i], col, -1)], array.slice(lines, i + 1, end + 1)))
	m := regex.find_all_string_submatch_n(`(?is)^<(?:script|link)\b[^>]*>?`, joined, 1)
	count(m) > 0
	t := m[0][0]
}

_attr(tag, name) := v if {
	m := regex.find_all_string_submatch_n(concat("", [`(?is)\s`, name, `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`]), tag, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2], m[0][3]])
}

_remote_url(tag, kind) := u if {
	kind == "script"
	u := _attr(tag, "src")
	regex.match(`^(?:https?:)?//[A-Za-z0-9]`, u)
}

_remote_url(tag, kind) := u if {
	kind == "link"
	regex.match(`(?i)\bstylesheet\b`, _attr(tag, "rel"))
	u := _attr(tag, "href")
	regex.match(`^(?:https?:)?//[A-Za-z0-9]`, u)
}

# The tag at column col of line i sits inside an HTML comment: within the 30
# lines before it, the last "<!--" comes after the last "-->".
_in_html_comment(lines, i, col) if {
	start := max([0, i - 30])
	before := concat("\n", array.concat(array.slice(lines, start, i), [substring(lines[i], 0, col)]))
	opens := indexof_n(before, "<!--")
	count(opens) > 0
	closes := array.concat([-1], indexof_n(before, "-->"))
	max(opens) > max(closes)
}

findings contains finding if {
	some path, content in input.file_contents
	_template(path)
	contains(content, "//")
	_has_tag(content)
	regex.match(`(?i)<(?:script|link)\b[^>]*?\s(?:src|href)\s*=\s*["']?(?:https?:)?//`, content)
	lines := split(content, "\n")
	some i, line in lines
	_has_tag(line)
	lower_line := lower(line)
	some kind in {"script", "link"}
	some col in indexof_n(lower_line, concat("", ["<", kind]))
	tag := _tag(lines, i, col)
	u := _remote_url(tag, kind)
	not regex.match(_local_hosts, u)
	# integrity="...", and a framework binding of it (:integrity, v-bind:integrity, [attr.integrity])
	not regex.match(`(?i)[\s:\[.]integrity\]?\s*=`, tag)
	not regex.match(_dynamic_hosts, u)
	not _in_html_comment(lines, i, col)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Third-party %s loaded from %s without an integrity= (Subresource Integrity) hash: a compromised CDN can change the code this page runs", [_what(kind), u]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_what("script") := "script"

_what("link") := "stylesheet"

_has_tag(s) if contains(s, "<script")

_has_tag(s) if contains(s, "<link")

_has_tag(s) if contains(s, "<SCRIPT")

_has_tag(s) if contains(s, "<LINK")
