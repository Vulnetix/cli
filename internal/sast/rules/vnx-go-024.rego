package vulnetix.rules.vnx_go_024

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-024",
	"name": "Request parameter reaches a dangerous sink without validation",
	"description": "A value read from an HTTP request reaches a command, SQL text, file path, outbound request, redirect or raw response in the same function with no validation on the way. Sources: r.FormValue, r.PostFormValue, r.URL.Query().Get, r.Header.Get, r.PathValue (also through gin/echo's c.Request), mux.Vars(r)[...], chi.URLParam, httprouter ps.ByName, and gin/echo/fiber c.Query/c.DefaultQuery/c.Param/c.PostForm/c.FormValue/c.QueryParam. Sinks: exec.Command(Context), the query argument of db/tx/conn/stmt Exec/Query/QueryRow(Context), os.Open/OpenFile/ReadFile/Create/Remove/RemoveAll/Stat/WriteFile, ioutil.ReadFile/WriteFile, http.Get/Post/Head/NewRequest(WithContext), http.Redirect and gin/echo c.Redirect, fmt.Fprint*(w, ...) and w.Write on a writer named w, rw, res, resp or writer. The value may be read inline at the sink, through the variable it was assigned to, or through one further assignment (script := \"ping \" + host); a sink call broken across lines is read up to its closing parenthesis (four continuation lines) and reported on its first line. Not reported: a value passed as a bind argument after the query, converted (strconv), escaped or confined (url.QueryEscape, html.EscapeString, filepath.Base/Clean) where it is read, a variable checked between the read and the sink (regexp MatchString, an allowlist map lookup, a validate/sanitise call), values only logged or compared, a length (len) or comparison result assigned from the value, an html/template trusted-content conversion (template.HTML/JS/URL of a request value, reported by VNX-GO-020), comments and test files. This is a broad one-hop check; the dedicated rules for each sink (VNX-GO-002, 003, 005, 006, 007, 020, 021, 023, 025, 027) judge each weakness more precisely.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-024/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [20],
	"capec": ["CAPEC-101"],
	"attack_technique": ["T1195"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["input-validation", "http", "request"],
}

_lit_re := "\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\\\n]|\\\\.)+'"

_strip(s) := regex.replace(s, _lit_re, `""`)

_source_re := `\b(?:r|req|request|(?:c|ctx)\.Request)\.(?:(?:FormValue|PostFormValue|PathValue|Form\.Get|PostForm\.Get|Header\.Get)\(|URL\.Query\(\)\.Get\()|\bmux\.Vars\(\s*\w+\s*\)\[|\bchi\.URLParam\(|\b\w+\.ByName\(|\b(?:c|ctx)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

_db_re := `\b\w*(?:db|DB|tx|Tx|conn|Conn|stmt|Stmt|pool|Pool)\w*\.(?:Exec|Query|QueryRow)(Context)?\(`

_sink_re := `\bexec\.Command(?:Context)?\(|\bos\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|Stat|WriteFile)\(|\bioutil\.(?:ReadFile|WriteFile)\(|\bhttp\.(?:Redirect|Get|Post|Head|NewRequest|NewRequestWithContext)\(|\bfmt\.Fprint(?:f|ln)?\(\s*(?:w|rw|res|resp|writer)\s*,|\b(?:w|rw|res|resp|writer)\.Write\(|\b(?:c|ctx)\.Redirect\(`

# html/template trusted-content conversions are judged by VNX-GO-020, which
# owns that sink; their result is still not the parameter's text.
_conv_re := `\btemplate\.(?:HTML|JS|URL)\(`

_validated_re := `(?i)validat|sanitiz|sanitis|escape|filepath\.(?:Clean|Base|Rel|IsLocal)\(|path\.(?:Clean|Base)\(|strconv\.|\.MatchString\(|allow|whitelist|safe`

_balanced(pre) if {
	strings.count(pre, "(") == strings.count(pre, ")")
	strings.count(pre, "[") == strings.count(pre, "]")
	strings.count(pre, "{") == strings.count(pre, "}")
}

_split_top(s, sep) := pieces if {
	cuts := [p | some p in indexof_n(s, sep); _balanced(substring(s, 0, p))]
	bounds := array.concat(array.concat([-1], cuts), [count(s)])
	pieces := [trim_space(substring(s, bounds[k] + 1, (bounds[k + 1] - bounds[k]) - 1)) |
		some k in numbers.range(0, count(bounds) - 2)
	]
}

_inside(rest) := substring(rest, 0, min(closes)) if {
	closes := [p | some p in indexof_n(rest, ")"); _balanced(substring(rest, 0, p))]
	count(closes) > 0
}

_inside(rest) := rest if {
	closes := [p | some p in indexof_n(rest, ")"); _balanced(substring(rest, 0, p))]
	count(closes) == 0
}

# The text of the sink line that can carry the value: the query argument of a
# database call, the whole line otherwise.
_sink_text(code) := q if {
	m := regex.find_all_string_submatch_n(concat("", [`^[\s\S]*?`, _db_re]), code, 1)
	count(m) > 0
	args := _split_top(_inside(substring(code, count(m[0][0]), -1)), ",")
	q := _query_arg(args, m[0][1])
}

_sink_text(code) := code if {
	not regex.match(_db_re, code)
	regex.match(_sink_re, code)
}

_query_arg(args, "") := args[0]

_query_arg(args, "Context") := args[1] if count(args) > 1

_fn_start(lines, i) := max(array.concat([max([0, i - 60])], [j |
	some j in numbers.range(max([0, i - 60]), i)
	regex.match(`^func |\bfunc\s*\(`, lines[j])
]))

_assigned(l) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?::=|=)\s*(.*)$`, l, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
	not regex.match(_validated_re, m[0][2])

	# a length or a comparison result carries no text of the parameter
	not regex.match(`^\s*len\(|[=!]=|\bstrings\.(?:HasPrefix|HasSuffix|Contains|EqualFold)\(`, m[0][2])

	# the result of a sink (file contents, a response) is not the parameter
	not regex.match(_sink_re, m[0][2])
	not regex.match(_conv_re, m[0][2])
	not regex.match(_db_re, m[0][2])
}

_word(v) := concat("", [`\b`, v, `\b`])

# The sink call's text, with up to four continuation lines when the call is
# broken after "(" or ",".
_stmt(_, _, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := concat(" ", [line, _inside(rest), ")"]) if {
	regex.match(`[(,]\s*$`, line)
	rest := _strip(concat(" ", [l |
		some l in array.slice(lines, i + 1, min([count(lines), i + 5]))
		not helpers.is_comment_line(l)
	]))
}

# [variable, line it was assigned on]
_tainted(lines, src, fs, i) := direct | hop if {
	direct := {[v, j] |
		some j in src
		j >= fs
		j < i
		v := _assigned(lines[j])
	}
	hop := {[w, k] |
		some d in direct
		some k in numbers.range(d[1] + 1, i - 1)
		l := lines[k]
		contains(l, d[0])
		not helpers.is_comment_line(l)
		w := _assigned(l)
		w != d[0]
		regex.match(_word(d[0]), regex.replace(l, `^[^=]*=`, ""))
	}
}

# A check on v between its assignment and the sink.
_guarded(lines, v, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(_word(v), l)
	not helpers.is_comment_line(l)
	_guard_line(l, v)
}

_guard_line(l, _) if regex.match(_validated_re, l)

_guard_line(l, v) if regex.match(concat("", [`^\s*(?:if|switch)\b.*\w\[\s*`, v, `\s*\]`]), l)

_reaches(lines, src, fs, i, text) if regex.match(_source_re, text)

_reaches(lines, src, fs, i, text) if {
	some t in _tainted(lines, src, fs, i)
	regex.match(_word(t[0]), text)
	not _guarded(lines, t[0], t[1], i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(_source_re, content)
	regex.match(`exec\.Command|\.(?:Exec|Query|QueryRow)(?:Context)?\(|\bos\.|ioutil\.|http\.(?:Redirect|Get|Post|Head|NewRequest)|fmt\.Fprint|w\.Write\(|\.Redirect\(`, content)
	lines := split(content, "\n")
	src := [j | some j, l in lines; regex.match(_source_re, l); not helpers.is_comment_line(l)]
	count(src) > 0
	some i, line in lines
	regex.match(`exec\.|\.(?:Exec|Query|QueryRow)|os\.|ioutil\.|http\.|Fprint|w\.Write|\.Redirect\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(_stmt(lines, i, line))
	text := _sink_text(code)
	not regex.match(_validated_re, text)
	fs := _fn_start(lines, i)
	_reaches(lines, src, fs, i, text)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request parameter reaches a command, query, file path, outbound request, redirect or response without validation; validate or sanitise it first",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
