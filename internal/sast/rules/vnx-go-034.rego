package vulnetix.rules.vnx_go_034

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-034",
	"name": "OAuth redirect URI without validation against allowlist",
	"description": "An OAuth redirect URI taken from the request is used without being compared with the client's registered redirect URIs, so an attacker who controls it receives the authorization code or token. Reported: http.Redirect, gin/echo c.Redirect(code, url), fiber c.Redirect(url) or a Location header whose destination contains the value of a redirect_uri, redirect_url, post_logout_redirect_uri or callback_url request parameter (r.URL.Query().Get, q.Get, r.FormValue, r.PostFormValue, r.Form.Get, gin c.Query/DefaultQuery/PostForm, echo c.QueryParam/FormValue), inline or through a variable assigned from it in the 30 lines above, including after a ?code= or #access_token= suffix is appended; an oauth2.Config RedirectURL set from any request value; and oauth2.SetAuthURLParam(\"redirect_uri\", <request value>). Not reported: a value compared in between (==, !=, slices.Contains, strings.HasPrefix, url.Parse, a map lookup, a helper named allowed/registered/valid/allowlist), constant or configured redirect URLs, parameters with other names (generic open redirects are VNX-GO-005 and VNX-GO-025), comments and string literals. Cross-function flows are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-034/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-610"],
	"attack_technique": ["T1046"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["oauth", "redirect-uri", "validation", "allowlist"],
}

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_reader := `(?:\b(?:r|req|request)\.(?:FormValue|PostFormValue)\(|\b(?:r|req|request)\.URL\.Query\(\)\.Get\(|\.(?:Form|PostForm)\.Get\(|\b(?:q|query|params|values|v)\.Get\(|\b(?:c|ctx)\.(?:Query|DefaultQuery|PostForm|QueryParam|FormValue)\()`

# Any request value.
_any_src := concat("", [_reader, `\s*"[^"]*"`])

# A request value read from an OAuth redirect parameter.
_oauth_src := concat("", [_reader, `\s*"(?i:(?:post_logout_)?redirect_?ur[il]|callback_?url)"`])

_redirect_sink := `\bhttp\.Redirect\(|\b(?:c|ctx)\.Redirect\(|\.Header\(\)\.(?:Set|Add)\(\s*"Location"`

_config_sink := `\bRedirectURL\s*(?::|=[^=])|\bSetAuthURLParam\(\s*"redirect_uri"`

_guard := `==|!=|\bContains\w*\(|HasPrefix\(|\burl\.Parse\(|(?i:allow|registered|valid|whitelist|trusted)`

_word(v) := concat("", [`\b`, v, `\b`])

_depth(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The sink's text up to where its parentheses close (at most 4 lines on).
_call(lines, i) := lines[i] if _depth(_code(lines[i])) <= 0

_call(lines, i) := txt if {
	_depth(_code(lines[i])) > 0
	end := min([count(lines) - 1, i + 4])
	end >= i + 1
	ks := [k |
		some k in numbers.range(i + 1, end)
		_depth(concat("\n", [_code(lines[j]) | some j in numbers.range(i, k)])) <= 0
	]
	stop := array.concat(ks, [end])[0]
	txt := concat("\n", [lines[j] | some j in numbers.range(i, stop)])
}

# The part of the sink line after the sink itself (the destination).
_dest(lines, i, sink_re) := d if {
	txt := _call(lines, i)
	ms := regex.find_all_string_submatch_n(sink_re, txt, 1)
	count(ms) > 0
	d := substring(txt, indexof(txt, ms[0][0]) + count(ms[0][0]), -1)
}

_guarded(lines, i, v) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_word(v), l)
	regex.match(_guard, _code(l))
	not regex.match(concat("", [`^\s*`, v, `\s*:?=`]), l)
}

_flows(lines, i, sink_re, src_re) if {
	d := _dest(lines, i, sink_re)
	regex.match(src_re, d)
}

_flows(lines, i, sink_re, src_re) if {
	d := _dest(lines, i, sink_re)
	some v in _tainted(lines, i, src_re)
	regex.match(_word(v), _code(d))
	not _guarded(lines, i, v)
}

# Variables assigned from a source in the 30 lines above. An authorization
# URL built for the identity provider (AuthCodeURL) is the provider's request,
# not a redirect to the parameter's value.
_tainted(lines, i, src_re) := {v |
	some j in numbers.range(max([0, i - 30]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(src_re, prev)
	not contains(prev, "AuthCodeURL(")
	v := helpers.assigned_first(prev)
}

_hit(lines, i, code) if {
	regex.match(`\bhttp\.Redirect\(|\b(?:c|ctx)\.Redirect\(|\.Header\(\)\.(?:Set|Add)\(`, code)
	regex.match(_redirect_sink, lines[i])
	_flows(lines, i, _redirect_sink, _oauth_src)
}

_hit(lines, i, code) if {
	regex.match(`\bRedirectURL\b|\bSetAuthURLParam\(`, code)
	regex.match(_config_sink, lines[i])
	_flows(lines, i, _config_sink, _any_src)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)redirect_?ur[il]|callback_?url`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Redirect|Location|SetAuthURLParam`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	_hit(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "OAuth redirect URI from the request is used without checking it against the client's registered redirect URIs; an attacker can have the code or token delivered to their own site",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
