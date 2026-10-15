package vulnetix.rules.vnx_go_020

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-020",
	"name": "Use of template.HTML with potential user input",
	"description": "An html/template trusted-content conversion (template.HTML, HTMLAttr, JS, JSStr, CSS, URL, Srcset), which switches off contextual escaping for its value, is applied to something that is not the developer's own constant markup. Reported when the argument is an HTTP request value (r.FormValue, r.URL.Query().Get, r.Header.Get, mux.Vars, chi.URLParam, gin/echo c.Query/c.Param/c.PostForm/c.FormValue); markup assembled with fmt.Sprintf (with a %s/%v verb or a non-literal format) or + concatenation of a variable; a parameter of the enclosing function or func literal (a raw-HTML helper or FuncMap entry marks whatever every caller passes as safe); or a variable assigned in the function from any of those, including through a non-sanitising transformation of a request value such as a markdown renderer (rendered := blackfriday.Run([]byte(src))) (term := r.FormValue(...); msg := fmt.Sprintf(\"<b>%s</b>\", term); template.HTML(msg)). Not reported: string literals and concatenations of literals or of numeric conversions (strconv.Itoa, len), package constants and variables, values passed through an HTML sanitiser or escaper (bluemonday Sanitize, html.EscapeString, template.HTMLEscapeString) directly or via a variable, the output of executing a template (buf.String()), struct fields read without concatenation (their origin is not visible on the line), the type used in declarations, assertions and signatures, string literals mentioning the call, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-020/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xss", "template", "html"],
}

_conv_re := `\btemplate\.(?:HTML|HTMLAttr|JS|JSStr|CSS|URL|Srcset)\((.*)$`

_source_re := `\b(?:r|req|request|(?:c|ctx)\.Request)\.(?:(?:FormValue|PostFormValue|PathValue|URL\.RawQuery|URL\.Path|Form\.Get|PostForm\.Get|Header\.Get|Referer|UserAgent|Cookie)\b|URL\.Query\(\))|\b(?:c|ctx)\.(?:Query|DefaultQuery|PostForm|DefaultPostForm|Param|Params|FormValue|QueryParam|GetHeader|Cookie)\(|\bmux\.Vars\(|\bchi\.URLParam\(|\.ByName\(|ReadAll\(\s*(?:r|req|request)\.Body`

_safe_re := `(?i)sanitiz|escape|bluemonday|QuoteLiteral`

# String literals reduced to "" so their contents (markup, prose) are not
# mistaken for code.
_strip(s) := regex.replace(s, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\]|\\\\.)'", `""`)

# The argument of the call whose text after the opening paren is rest.
_arg(rest) := a if {
	closes := [k |
		some k in numbers.range(0, count(rest) - 1)
		substring(rest, k, 1) == ")"
		pre := substring(rest, 0, k)
		strings.count(pre, "(") == strings.count(pre, ")")
	]
	a := _upto(rest, closes)
}

_upto(rest, closes) := substring(rest, 0, closes[0]) if count(closes) > 0

_upto(rest, closes) := rest if count(closes) == 0

# Bare identifier, string(x) or x.(string).
_root(arg) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:string\(\s*)?([A-Za-z_]\w*)\s*(?:\.\(\s*string\s*\))?\s*\)?\s*$`, arg, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"nil", "true", "false"}
}

# An expression (literals stripped) that is request data or markup built from
# a variable. raw is the unstripped text, for reading a Sprintf format.
_direct_bad(code, _) if regex.match(_source_re, code)

_direct_bad(code, raw) if {
	contains(code, "Sprintf(")
	not _int_only_sprintf(raw)
	regex.match(`Sprintf\(\s*(?:[A-Za-z_]|""\s*,\s*[^)\s])`, code)
}

_direct_bad(code, _) if regex.match(`\+\s*[A-Za-z_]|[A-Za-z_][\w\.\)\]]*\s*\+`, _numbers_out(code))

# Numeric conversions concatenated into markup cannot carry markup.
_numbers_out(code) := regex.replace(code, `\bstrconv\.(?:Itoa|FormatInt|FormatUint|FormatFloat|FormatBool)\([^()]*\)|\blen\([^()]*\)`, `""`)

# fmt.Sprintf("<b>%d</b>", n): only integer verbs in a literal format.
_int_only_sprintf(raw) if regex.match(`Sprintf\(\s*"(?:[^"%\\]|\\.|%%|%[0-9]*d)*"`, raw)

_params(lines, i) := ps if {
	sigs := [j |
		some j in numbers.range(max([0, i - 80]), i)
		contains(lines[j], "func")
		regex.match(`\bfunc\b\s*(?:\([^)]*\)\s*)?\w*\s*\(`, lines[j])
	]
	count(sigs) > 0
	sig := _strip(lines[max(sigs)])
	m := regex.find_all_string_submatch_n(`\bfunc\b\s*(?:\([^)]*\)\s*)?\w*\s*\(([^)]*)\)`, sig, -1)
	count(m) > 0
	ps := {n |
		some piece in split(m[count(m) - 1][1], ",")
		words := regex.split(`\s+`, trim_space(piece))
		n := words[0]
		n != ""
	}
}

_is_param(lines, i, v) if v in _params(lines, i)

_fn_start(lines, i) := max(array.concat([max([0, i - 80])], [j |
	some j in numbers.range(max([0, i - 80]), i)
	startswith(lines[j], "func ")
]))

# Right-hand sides assigned to v in the function above line i.
_rhs(lines, fs, i, v) := {[_strip(r[0][1]), r[0][1]] |
	i - 1 >= fs
	re := concat("", [`^\s*(?:var\s+)?`, v, `(?:\s*,\s*\w+)*\s*(?:\s[\w\.\*\[\]]+\s*)?(?::=|=|\+=)\s*(.*)$`])
	some j in numbers.range(fs, i - 1)
	contains(lines[j], v)
	not helpers.is_comment_line(lines[j])
	r := regex.find_all_string_submatch_n(re, lines[j], 1)
	count(r) > 0
}

_bad_var(lines, fs, i, v) if {
	rhs := _rhs(lines, fs, i, v)
	not _assigned_safe(rhs)
	some pair in rhs
	_direct_bad(pair[0], pair[1])
}

# v := otherParam / v := tainted (one more hop)
_bad_var(lines, fs, i, v) if {
	rhs := _rhs(lines, fs, i, v)
	not _assigned_safe(rhs)
	some pair in rhs
	w := _root(pair[0])
	w != v
	_bad_ident(lines, fs, i, w)
}

# v := render(x) where x was read from the request: a transformation that is
# not a sanitiser or a numeric conversion (a markdown renderer, ToUpper,
# []byte) keeps the markup the requester chose.
_bad_var(lines, fs, i, v) if {
	rhs := _rhs(lines, fs, i, v)
	not _assigned_safe(rhs)
	some pair in rhs
	not regex.match(`\bstrconv\.|\blen\(|\b(?:u?int(?:8|16|32|64)?|float(?:32|64)|bool)\(`, pair[0])
	some w in regex.find_n(`\b[A-Za-z_]\w*\b`, pair[0], -1)
	w != v
	_request_var(lines, fs, i, w)
}

_request_var(lines, fs, i, w) if {
	rhs := _rhs(lines, fs, i, w)
	not _assigned_safe(rhs)
	some pair in rhs
	regex.match(_source_re, pair[0])
}

_assigned_safe(rhs) if {
	some pair in rhs
	regex.match(_safe_re, pair[0])
}

_bad_ident(lines, _, i, v) if _is_param(lines, i, v)

_bad_ident(lines, fs, i, v) if {
	rhs := _rhs(lines, fs, i, v)
	not _assigned_safe(rhs)
	some pair in rhs
	_direct_bad(pair[0], pair[1])
}

# The argument itself is bad, or it is a parameter or a variable assigned
# from something bad.
_bad(arg, raw_arg, _, _, _) if {
	not regex.match(_safe_re, arg)
	_direct_bad(arg, raw_arg)
}

_bad(arg, _, lines, i, _) if {
	not regex.match(_safe_re, arg)
	v := _root(arg)
	_is_param(lines, i, v)
}

_bad(arg, _, lines, i, fs) if {
	not regex.match(_safe_re, arg)
	v := _root(arg)
	_bad_var(lines, fs, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "html/template")
	regex.match(`template\.(?:HTML|HTMLAttr|JS|JSStr|CSS|URL|Srcset)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "template.")
	not helpers.is_comment_line(line)
	code := _strip(line)
	m := regex.find_all_string_submatch_n(_conv_re, code, 1)
	count(m) > 0
	raw_m := regex.find_all_string_submatch_n(_conv_re, line, 1)
	raw_arg := _raw_arg(raw_m)
	arg := _arg(m[0][1])
	fs := _fn_start(lines, i)
	_bad(arg, raw_arg, lines, i, fs)
	finding := {
		"rule_id": metadata.id,
		"message": "template.HTML/JS/URL/CSS/HTMLAttr disables html/template escaping for a value built from request data, a function argument or formatted markup; pass the raw value to the template (it is escaped for its context) or sanitise it (bluemonday) first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_raw_arg(raw_m) := _arg(raw_m[0][1]) if count(raw_m) > 0

_raw_arg(raw_m) := "" if count(raw_m) == 0

