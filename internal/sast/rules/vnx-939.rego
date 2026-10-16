# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_939

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-939",
	"name": "Improper Authorization in Handler for Custom URL Scheme",
	"description": "An Android deep-link handler acts on the incoming link without checking where it points. Any app or web page can open a custom-scheme (myapp://) or app link, so the URI is attacker-chosen. Reported, in Java and Kotlin: the launching Intent's data (getIntent().getData()/getDataString(), intent.data/intent.dataString, intent?.data) or a query parameter or path segment read from it, passed to a WebView loadUrl/postUrl/loadDataWithBaseURL, parsed into an Intent with Intent.parseUri, or used to pick a component (setClassName, new ComponentName, Class.forName), directly, through up to two variable assignments in the 25 lines above, or as the parameter of a let/also/run lambda opened on the link (intent?.data?.let { webView.loadUrl(it.toString()) }). Not reported: a link whose host, scheme or value is checked first (getHost/host, getScheme/scheme, startsWith, equals, an allowlist or validator call) between the read and the sink (a null or emptiness test is not such a check); constant URLs; intent string extras (VNX-ANDROID-002 covers those for JavaScript-enabled WebViews); test code, comments and strings. Flows across methods or files are not followed, and the manifest's intent-filter is not read.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-939/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [939],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["deeplink", "android", "cwe-939"],
}

# The deep link itself, or a part read from a Uri.
_src := `(getIntent\(\)\s*\.\s*getData(String)?\(\)|\bintent\s*[!?]?\s*\.\s*(getData(String)?\(\)|data\b|dataString\b)|\.getQueryParameter\(|\.getQueryParameters\(|\.getPathSegments\(\)|\.getLastPathSegment\(\)|\?\.\s*getQueryParameter\(|\.lastPathSegment\b|\.pathSegments\b)`

_sink_re := `(\.(loadUrl|postUrl|loadDataWithBaseURL)\s*\(|\bIntent\s*\.\s*parseUri\s*\(|\.setClassName\s*\(|\bComponentName\s*\(|\bClass\s*\.\s*forName\s*\()(.*)$`

_guard_re := `(getHost\(\)|\.host\b|getScheme\(\)|\.scheme\b|getAuthority\(\)|\.authority\b|startsWith\(|\.equals\(|==|(?i)allow\w*|whitelist|trusted|isValid\w*|isSafe\w*|validate\w*|verify\w*)`

# A null or emptiness test is not a check on where the link points.
_no_null(l) := regex.replace(l, `[!=]==?\s*null\b|\bnull\s*[!=]==?|\.isEmpty\(\s*\)|\bisNullOrEmpty\(\s*\)|\bisNullOrBlank\(\s*\)|\bTextUtils\.isEmpty\(`, " ")

# intent?.data?.let { webView.loadUrl(it.toString()) }, or the lambda
# opened on a line up to 5 above the sink: { uri -> ... }.
_let_re := `^(.*?)\??\.\s*(?:let|also|run)\s*\{\s*(?:(\w+)\s*->)?`

_lambda_param(m) := "it" if m == ""

_lambda_param(m) := m if m != ""

_reaches(lines, i, args) if {
	some j in numbers.range(max([0, i - 5]), i)
	contains(lines[j], "{")
	m := regex.find_all_string_submatch_n(_let_re, lines[j], 1)
	count(m) > 0
	regex.match(_src, m[0][1])
	regex.match(_word(_lambda_param(m[0][2])), args)
	not _guarded(lines, j, i)
}

_args(line) := a if {
	m := regex.find_all_string_submatch_n(_sink_re, line, 1)
	count(m) > 0
	a := m[0][3]
}

_strip_strings(line) := regex.replace(line, `"([^"\\]|\\.)*"`, `""`)

# The sink's arguments; a call broken after its open parenthesis is read
# from the next two lines.
_call_args(_, _, line) := a if {
	a := _args(line)
	not regex.match(`^\s*$`, a)
}

_call_args(lines, i, line) := a if {
	regex.match(`^\s*$`, _args(line))
	a := concat(" ", [lines[k] | some k in numbers.range(i + 1, min([i + 2, count(lines) - 1]))])
}

_word(v) := concat("", [`\b`, v, `\b`])

# Names assigned from the deep link within 25 lines, plus names assigned
# from those (one more hop), each with the line it was assigned on.
_hop1(lines, i) := {[j, v] |
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src, l)
	v := helpers.assigned_first(l)
}

_hop2(lines, i, h1) := {[j0, w] |
	some [j0, v] in h1
	j0 + 1 <= i - 1
	some k in helpers.span(j0 + 1, i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(_word(v), l)
	not helpers.is_comment_line(l)
	w := helpers.assigned_first(l)
	w != v
}

_guarded(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_guard_re, _no_null(l))
}

_guarded(lines, j, _) if regex.match(_guard_re, _no_null(lines[j]))

_reaches(lines, i, args) if {
	regex.match(_src, args)
	not _guarded_inline(lines, i)
}

_guarded_inline(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*(if|\}?\s*else)\b`, lines[k])
	regex.match(_guard_re, _no_null(lines[k]))
}

_reaches(lines, i, args) if {
	h1 := _hop1(lines, i)
	some [j, v] in h1 | _hop2(lines, i, h1)
	regex.match(_word(v), args)
	not _guarded(lines, j, i)
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(java|kt)$`, path)
	not helpers.is_test_path(path)
	regex.match(`getData|intent\s*[!?]?\s*\.\s*data|getQueryParameter|PathSegment`, content)
	regex.match(`loadUrl|postUrl|loadDataWithBaseURL|parseUri|setClassName|ComponentName|forName`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`loadUrl|postUrl|loadDataWithBaseURL|parseUri|setClassName|ComponentName|forName`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip_strings(line))
	args := _call_args(lines, i, line)
	_reaches(lines, i, args)
	finding := {
		"rule_id": metadata.id,
		"message": "Deep-link URI is acted on without checking its host or value: any app or web page can open this link and choose what is loaded or launched. Validate the scheme and host (or the parameter) against an allowlist first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
