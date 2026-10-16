package vulnetix.rules.vnx_go_025

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-025",
	"name": "Potential open redirect via HTTP redirect",
	"description": "A redirect target is taken from the request: a query, form or route parameter (r.URL.Query().Get, r.FormValue, r.PostFormValue, r.Form.Get, mux.Vars, chi.URLParam, r.PathValue, httprouter ps.ByName, gin c.Query/DefaultQuery/PostForm/Param, echo c.QueryParam/FormValue, fiber c.Query/Params) reaches http.Redirect, a framework Redirect (gin/echo c.Redirect(code, url), fiber c.Redirect(url)) or a Location header, directly, through the variable it was assigned to, or through one variable built from it (\"/\" + v, fmt.Sprintf(\"https://%s/...\", v), a host without a trailing slash). Not reported: a target checked first (strings.HasPrefix, a switch or map allowlist, url.Parse followed by a Host/IsAbs/Scheme test, a helper whose name says safe/valid/allowed/trusted/sanitize), a value placed after a fixed path segment or a fixed scheme://host/ (\"/users/\" + v, \"https://docs.example.com/\" + v), a value passed through url.QueryEscape/PathEscape, constant targets, the request Host or Referer header (not attacker-chosen in a victim's browser), comments and string literals. Cross-function flows are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-025/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-610"],
	"attack_technique": ["T1046"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "http", "redirect"],
}

# A value the requester chooses in a link they send a victim.
_source := `\b(?:r|req|request|rq|httpReq)\.(?:FormValue|PostFormValue)\(|\.URL\.Query\(\)|\b(?:r|req|request|rq)\.(?:Form|PostForm)\.Get\(|\bmux\.Vars\(|\bchi\.URLParam\(|\.PathValue\(|\bps\.ByName\(|\b(?:c|ctx|e|g|context|this|self)\.(?:Query|DefaultQuery|GetQuery|PostForm|DefaultPostForm|GetPostForm|Param|Params|QueryParam|FormValue|GetString)\(`

_source_needles := ["FormValue", "URL.Query", "Form.Get", "mux.Vars", "URLParam(","PathValue", "ByName(", "Query(", "Param(", "Params(", "PostForm", "QueryParam", "GetString("]

_gate(content) if {
	some n in _source_needles
	contains(content, n)
}

# Redirect sinks. The match ends where the arguments begin.
_sink_re := `\bhttp\.Redirect\(|\b\w+\.Redirect\(|\.Redirect\(\)\.To\(|\bhttp\.RedirectHandler\(|\.Header\(\)\.(?:Set|Add)\(\s*"Location"\s*,|\.Header\(\)\["Location"\]\s*=`

_sink_hint(line) if contains(line, "Redirect")

_sink_hint(line) if contains(line, "\"Location\"")

# The arguments: the rest of the line, plus continuation lines of a call
# broken after '(' or ','.
_rest(lines, i, line, m) := r if {
	not regex.match(`[(,]\s*$`, line)
	r := substring(line, indexof(line, m) + count(m), -1)
}

_rest(lines, i, line, m) := r if {
	regex.match(`[(,]\s*$`, line)
	end := min([count(lines) - 1, i + 4])
	tail := concat(" ", [lines[k] | some k in numbers.range(i + 1, end)])
	r := concat(" ", [substring(line, indexof(line, m) + count(m), -1), tail])
}

# The URL argument first: drop http.Redirect's writer/request pair, or the
# status code a gin/echo/beego Redirect takes first.
_url_args(m, rest) := regex.replace(rest, `^\s*[\w\.]+\s*,\s*[\w\.]+\s*,\s*`, "") if contains(m, "http.Redirect(")

_url_args(m, rest) := regex.replace(rest, `^\s*(?:http\.Status\w+|fiber\.Status\w+|\d{3})\s*,\s*`, "") if not contains(m, "http.Redirect(")

# Code text: string literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The target cannot leave the site: it escapes the value, or a fixed path
# segment or a fixed scheme://host/ comes before it.
_safe_build(e) if regex.match(`url\.(?:QueryEscape|PathEscape)\(|\.Encode\(\)`, e)

_safe_build(e) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:fmt\.Sprintf\(\s*)?"([^"%]*)`, e, 1)
	count(m) > 0
	_fixed_prefix(m[0][1])
}

_fixed_prefix(p) if regex.match(`^/[^/\\]`, p)

_fixed_prefix(p) if regex.match(`^(?:https?:)?//[^/]+/`, p)

# Validation of a name before the redirect.
_guard_re := `strings\.HasPrefix\(|strings\.HasSuffix\(|\.IsAbs\(\)|\.Host\b|\.Hostname\(\)|\.Scheme\b|(?i:allow|whitelist|safe|valid|trusted|sanitiz|sanitis|islocal|isrelative|sameorigin|samehost|permitted)`

_word(n) := concat("", [`\b`, n, `\b`])

_guards(l, n) if {
	regex.match(_word(n), l)
	regex.match(_guard_re, l)
}

_guards(l, n) if regex.match(concat("", [`\[\s*`, n, `\s*\]`]), l)

_guards(l, n) if regex.match(concat("", [`^\s*switch\s+`, n, `\b`]), l)

_rhs(l) := substring(l, indexof(l, "=") + 1, -1)

# The window a flow is followed in: at most 25 lines up, never above the
# enclosing top-level func.
_lo(lines, i) := lo if {
	starts := [j | some j in numbers.range(max([0, i - 25]), i); startswith(lines[j], "func ")]
	lo := max(array.concat([max([0, i - 25])], starts))
}

_tainted(lines, i, lo) := {v |
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_source, l)
	not _lookup_key(l)
	v := helpers.assigned_first(l)
}

# dest, ok := allowed[r.URL.Query().Get("to")]: the request value is only
# the key of a lookup; the target is the table's value.
_lookup_key(l) if regex.match(`^\s*[A-Za-z_][\w\.]*\[`, _rhs(l))

# One propagation step: a variable assigned from an expression that names a
# tainted variable, unless the expression keeps the target on this site.
_derived(lines, i, lo, t1) := {v |
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	contains(l, "=")
	not helpers.is_comment_line(l)
	some t in t1
	regex.match(_word(t), _rhs(l))
	v := helpers.assigned_first(l)
	v != t
	not _safe_build(trim_left(_rhs(l), " \t"))
}

_guarded(lines, i, lo, names) if {
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	some n in names
	_guards(l, n)
}

_tainted_target(_, _, args) if {
	regex.match(_source, args)
	not regex.match(_guard_re, args)
}

_tainted_target(lines, i, args) if {
	lo := _lo(lines, i)
	t1 := _tainted(lines, i, lo)
	count(t1) > 0
	names := t1 | _derived(lines, i, lo, t1)
	some n in names
	regex.match(_word(n), args)
	not regex.match(_guard_re, args)
	not _guarded(lines, i, lo, names)
}

# Inside a /* ... */ block whose lines carry no leading '*'.
_in_block_comment(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 40]), i - 1)
	contains(lines[j], "/*")
	not contains(substring(lines[j], indexof(lines[j], "/*") + 2, -1), "*/")
	not _closed_between(lines, j, i)
}

_closed_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	contains(lines[k], "*/")
}

# A function of this file that passes one of its own parameters to
# http.Redirect as the target: a call to it is a redirect too.
_wrappers(lines) := {name |
	n := count(lines) - 1
	some j, l in lines
	startswith(l, "func ")
	hm := regex.find_all_string_submatch_n(`^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)`, l, 1)
	count(hm) > 0
	some k in numbers.range(min([j + 1, n]), min([j + 12, n]))
	contains(lines[k], "Redirect(")
	rm := regex.find_all_string_submatch_n(`\bhttp\.Redirect\(\s*[\w\.]+\s*,\s*[\w\.]+\s*,\s*(\w+)\s*,`, lines[k], 1)
	count(rm) > 0
	regex.match(_word(rm[0][1]), hm[0][2])
	name := hm[0][1]
	name != "Redirect"
}

# Redirect sink on line i: the URL arguments.
_sink_args(lines, i, line, _) := args if {
	_sink_hint(line)
	ms := regex.find_all_string_submatch_n(_sink_re, line, 1)
	count(ms) > 0
	m := ms[0][0]
	regex.match(`\bRedirect\(|\.Redirect\(\)|\.Header\(\)\.(?:Set|Add)\(\s*""|\.Header\(\)\[""\]`, _code(line))
	args := trim_left(_url_args(m, _rest(lines, i, line, m)), " \t")
}

_sink_args(lines, i, line, wrappers) := args if {
	some w in wrappers
	contains(line, w)
	not startswith(line, "func ")
	ms := regex.find_all_string_submatch_n(concat("", [`\b`, w, `\(`]), _code(line), 1)
	count(ms) > 0
	m := concat("", [w, "("])
	args := _rest(lines, i, line, m)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_gate(content)
	regex.match(`Redirect\(|"Location"`, content)
	lines := split(content, "\n")
	wrappers := _wrappers(lines)
	some i, line in lines
	not helpers.is_comment_line(line)
	some args in {a | a := _sink_args(lines, i, line, wrappers)}
	not _safe_build(args)
	_tainted_target(lines, i, args)
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect target comes from the request: an attacker can send victims a link on this site that forwards them to any site. Accept only relative paths (one leading '/', not '//' or '/\\') or hosts on an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
