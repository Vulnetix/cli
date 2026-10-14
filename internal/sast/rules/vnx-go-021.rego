package vulnetix.rules.vnx_go_021

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-021",
	"name": "Potential XSS via fmt.Fprintf with HTML tags",
	"description": "HTML markup is written straight to an HTTP response with a non-constant value spliced in unescaped. Reported writes: fmt.Fprintf with a %s/%v/%q verb, and fmt.Fprint/Fprintln, io.WriteString, w.Write([]byte(...)) and w.WriteString with + concatenation, whose writer is an http.ResponseWriter parameter of the file (w, rw, res, out...) or gin/echo's c.Writer / c.Response(); gin c.Data(status, \"text/html...\", []byte(...)); and echo c.HTML(status, markup) built by concatenation or fmt.Sprintf. A string literal of the call must contain an HTML tag (<p>, </a>, <!doctype), and the value may be a request value, a variable, a parameter or a struct field (stored XSS is the same bug). Calls spanning several lines and raw-string pages are read whole; the finding is on the call's first line. Not reported: values escaped or sanitised (html.EscapeString, template.HTMLEscapeString, bluemonday) directly or through a variable, numbers (%d, %f, strconv, len), string literals and constants, http.StatusText, a handler that sets Content-Type to text/plain or application/json first, writes to builders, files, stdout and stderr (generated documentation is not a browser response), formats with no HTML tag (plain text, JSON, comparisons, Hugo shortcodes), string literals mentioning the call, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-021/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xss", "html", "fmt"],
}

_lit_re := "\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\\\n]|\\\\.)+'"

_strip(s) := regex.replace(s, _lit_re, `""`)

_tag_re := `</?[A-Za-z!][\w-]*`

_safe_re := `(?i)escape|sanitiz|bluemonday|^strconv\.|^len\(|^cap\(|StatusText\(|^u?int\d*\(|^float\d*\(|template\.(?:HTML|JS|URL)\(`

_sinks := {
	"fprintf": `\bfmt\.Fprintf\(`,
	"fprint": `\bfmt\.Fprint(?:ln)?\(`,
	"iows": `\bio\.WriteString\(`,
	"write": `\b([A-Za-z_][\w\.]*(?:\(\))?(?:\.Writer)?)\.Write(?:String)?\(`,
	"data": `\b(?:c|ctx)\.Data\(`,
	"echo": `\b(?:c|ctx)\.HTML\(`,
}

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

# Text inside the parens that rest (the text after an opening paren) opens.
_inside(rest) := substring(rest, 0, min(closes)) if {
	closes := [p | some p in indexof_n(rest, ")"); _balanced(substring(rest, 0, p))]
	count(closes) > 0
}

# Number of literals in args before index k.
_off(args, k) := sum([strings.count(args[j], `""`) | some j in numbers.range(0, k - 1)]) if k > 0

_off(_, 0) := 0

_fn_start(lines, i) := max(array.concat([max([0, i - 200])], [j |
	some j in numbers.range(max([0, i - 200]), i)
	startswith(lines[j], "func ")
]))

_consts(content, lines) := cs if {
	single := {m[1] | some m in regex.find_all_string_submatch_n(`(?m)^\s*const\s+(\w+)`, content, -1)}
	starts := [j | some j, l in lines; regex.match(`^\s*const\s*\(\s*$`, l)]
	block := {n |
		some s in starts
		some j in numbers.range(s + 1, min([count(lines) - 1, s + 60]))
		not _block_ended(lines, s, j)
		r := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\b`, lines[j], 1)
		count(r) > 0
		n := r[0][1]
	}
	cs := single | block
}

_block_ended(lines, s, j) if {
	some k in numbers.range(s + 1, j)
	regex.match(`^\s*\)`, lines[k])
}

_safe_vars(lines, fs, i) := {r[0][1] |
	i - 1 >= fs
	some j in numbers.range(fs, i - 1)
	r := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:,\s*\w+\s*)?:?=\s*(.*)$`, lines[j], 1)
	count(r) > 0
	regex.match(_safe_re, trim_space(r[0][2]))
}

_operand_bad(op, ctx) if {
	op != `""`
	op != ""
	regex.match(`^[A-Za-z_]`, op)
	not regex.match(_safe_re, op)
	not op in ctx.consts
	not op in ctx.safe
	not op in {"nil", "true", "false"}
	not regex.match(`^[A-Za-z_]\w*\.[A-Z][A-Za-z]*Status\w*$`, op)
}

_verbs(raw) := [v[1] |
	some v in regex.find_all_string_submatch_n(`%[-+# 0]*(?:\[\d+\])?(?:\d+|\*)?(?:\.(?:\d+|\*))?([a-zA-Z%])`, raw, -1)
	v[1] != "%"
]

_fmt_bad(raw, values, ctx) if {
	vs := _verbs(raw)
	some k, v in vs
	v in {"s", "v", "q"}
	k < count(values)
	_operand_bad(values[k], ctx)
}

_unbyte(a) := substring(a, 7, count(a) - 8) if {
	startswith(a, "[]byte(")
	endswith(a, ")")
}

_unbyte(a) := a if not startswith(a, "[]byte(")

_content_bad(a0, lits, off, ctx) if {
	a := _unbyte(a0)
	startswith(a, "fmt.Sprintf(")
	inner := _inside(substring(a, 12, -1))
	iargs := _split_top(inner, ",")
	iargs[0] == `""`
	_fmt_bad(lits[off], array.slice(iargs, 1, count(iargs)), ctx)
}

_content_bad(a0, _, _, ctx) if {
	a := _unbyte(a0)
	not startswith(a, "fmt.Sprintf(")
	some op in _split_top(a, "+")
	_operand_bad(op, ctx)
}

_resp_writer(w, _) if regex.match(`^(?:c|ctx)\.(?:Writer|Response\(\)(?:\.Writer)?)$`, w)

_resp_writer(w, content) if {
	regex.match(`^[A-Za-z_]\w*$`, w)
	regex.match(concat("", [`\b`, w, `\s+http\.ResponseWriter\b`]), content)
}

_bad_call("fprintf", args, lits, _, ctx) if {
	_resp_writer(args[0], ctx.content)
	args[1] == `""`
	_fmt_bad(lits[_off(args, 1)], array.slice(args, 2, count(args)), ctx)
}

_bad_call("fprint", args, lits, _, ctx) if {
	_resp_writer(args[0], ctx.content)
	some k in numbers.range(1, count(args) - 1)
	_content_bad(args[k], lits, _off(args, k), ctx)
}

_bad_call("iows", args, lits, _, ctx) if {
	count(args) == 2
	_resp_writer(args[0], ctx.content)
	_content_bad(args[1], lits, _off(args, 1), ctx)
}

_bad_call("write", args, lits, recv, ctx) if {
	count(args) == 1
	_resp_writer(recv, ctx.content)
	_content_bad(args[0], lits, 0, ctx)
}

_bad_call("data", args, lits, _, ctx) if {
	count(args) == 3
	contains(ctx.content, "github.com/gin-gonic/gin")
	args[1] == `""`
	contains(lits[_off(args, 1)], "text/html")
	_content_bad(args[2], lits, _off(args, 2), ctx)
}

_bad_call("echo", args, lits, _, ctx) if {
	count(args) == 2
	contains(ctx.content, "github.com/labstack/echo")
	_content_bad(args[1], lits, _off(args, 1), ctx)
}

_plain_handler(lines, fs, i) if {
	some j in numbers.range(fs, i)
	contains(lines[j], "Content-Type")
	regex.match(`(?i)"(?:text/plain|application/json|text/csv|application/xml|text/xml)`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`fmt\.Fprint|\.Write(?:String)?\(|\.Data\(|\.HTML\(`, content)
	regex.match(`</?[A-Za-z!]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Fprint|Write|\.Data\(|\.HTML\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some kind, sre in _sinks
	sm := regex.find_all_string_submatch_n(sre, code, 1)
	count(sm) > 0
	recv := _recv(sm[0])
	t := concat("\n", array.slice(lines, i, i + 12))
	pm := regex.find_all_string_submatch_n(concat("", [`^[\s\S]*?`, sre]), t, 1)
	count(pm) > 0
	r := substring(t, count(pm[0][0]), -1)
	rs := _strip(r)
	call := _inside(rs)
	nlit := strings.count(call, `""`)
	lits := array.slice([x[0] | some x in regex.find_all_string_submatch_n(_lit_re, r, -1)], 0, nlit)
	some lit in lits
	regex.match(_tag_re, lit)
	args := _split_top(call, ",")
	fs := _fn_start(lines, i)
	not _plain_handler(lines, fs, i)
	ctx := {"content": content, "consts": _consts(content, lines), "safe": _safe_vars(lines, fs, i)}
	_bad_call(kind, args, lits, recv, ctx)
	finding := {
		"rule_id": metadata.id,
		"message": "HTML is written to the response with an unescaped value spliced in; render it with html/template or escape the value with html.EscapeString",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_recv(m) := m[1] if count(m) > 1

_recv(m) := "" if count(m) == 1
