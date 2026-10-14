package vulnetix.rules.vnx_go_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-012",
	"name": "Go HTTP response header set from a request parameter",
	"description": "A value an attacker can put in a link (query string, form field, route parameter: r.URL.Query().Get, q.Get/q[k] on q := r.URL.Query(), FormValue, PostFormValue, Form.Get, mux.Vars, chi.URLParam, r.PathValue, gin/echo/fiber Query/Param/FormValue, fasthttp QueryArgs().Peek) is written into a response header (w.Header().Set/Add, w.Header()[k] = ..., gin c.Header, echo c.Response().Header().Set, fiber c.Set/c.Append, fasthttp ctx.Response.Header.Set/Add), inline or through a variable assigned from it in the same function, with no neutralising step. Where header values are written raw, CR/LF in the value splits the response; net/http replaces CR and LF with spaces when it writes headers, so on net/http-based servers the attacker chooses the header's content (Location, Content-Disposition filename, Content-Language) but cannot add headers. A length or emptiness check (if len(next) == 0 { next = \"/\" }) does not neutralise the value and is still reported. Not reported: values passed through url.QueryEscape/PathEscape, url.Parse (which rejects control characters), a parse that validates them (uuid.Parse, netip.Parse*, time.Parse, mail.ParseAddress), strconv, mime.FormatMediaType, %q formatting, a CR/LF replacer or ContainsAny guard, an allow-list map lookup or switch; values derived through len(), a mime function or a hash; constant or server-derived values; values echoed from the request's own headers (a client can only affect its own response); headers set on outbound requests; gin's c.Set (a context value); comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-012/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [113],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["header-injection", "crlf", "go"],
}

# Link-controllable request values.
_src := `\.URL\.Query\(\)\.Get\(|\.URL\.Query\(\)\[|\.(?:FormValue|PostFormValue)\(|\.(?:Form|PostForm)\.Get\(|\.(?:Form|PostForm)\[|\bmux\.Vars\(|\bchi\.URLParam\(|\.PathValue\(|\.(?:QueryArgs|PostArgs)\(\)\.Peek\(|\b(?:c|ctx|ec|gc|e)\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|QueryParam|FormValue)\(\s*"`

# Response-header writes. Fiber's c.Set/c.Append and gin's c.Header are
# gated on the handler's context type below.
_sink_std := `\.Header\(\)\.(?:Set|Add)\(|\.Header\(\)\[[^\]]+\]\s*=|\.Response\.Header\.(?:Set|Add|SetCanonical)\(`

_sink_gin := `\b(?:c|ctx|gc)\.Header\(`

_sink_fiber := `\b(?:c|ctx)\.(?:Set|Append)\(`

_sink_any := concat("|", [_sink_std, _sink_gin, _sink_fiber])

# Steps that neutralise or constrain the value.
_clean := `url\.(?:QueryEscape|PathEscape|Parse|ParseRequestURI)\(|\b(?:uuid|netip|net|time|mail|semver)\.(?:Parse|MustParse)\w*\(|strconv\.|\bmime\.\w+\(|\blen\(|\b(?:sha1|sha256|sha512|md5|fnv|crc32|xxhash)\.|%q|strings\.(?:NewReplacer|ReplaceAll|Replace|Map|ContainsAny|ContainsRune|IndexAny|IndexByte|Contains)\(|httpguts\.|textproto\.|(?i:sanitiz|sanitis|validat|allowlist|allowed|whitelist)|regexp\.|\.MatchString\(|html\.EscapeString\(|base64\.|hex\.EncodeToString\(`

# Cheap substring tests before any regular expression: whole-file regexes with
# these alternations cost more than the rest of the rule.
_sink_gate(content) if contains(content, ".Header().")

_sink_gate(content) if contains(content, ".Header()[")

_sink_gate(content) if contains(content, "Response.Header.")

_sink_gate(content) if contains(content, "gin.Context")

_sink_gate(content) if contains(content, "fiber.Ctx")

_src_gate(s) if contains(s, ".URL.Query()")

_src_gate(s) if contains(s, "FormValue(")

_src_gate(s) if contains(s, "Form.Get(")

_src_gate(s) if contains(s, "Form[")

_src_gate(s) if contains(s, "mux.Vars(")

_src_gate(s) if contains(s, "chi.URLParam(")

_src_gate(s) if contains(s, ".PathValue(")

_src_gate(s) if contains(s, "Args().Peek(")

_src_gate(s) if regex.match(`\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|QueryParam)\("`, s)

# Start of the enclosing top-level function.
_fn_start(lines, i) := max(array.concat([0], [j | some j in numbers.range(0, i); startswith(lines[j], "func ")]))

# Something other than string literals follows the sink (or the call continues
# on the next line): w.Header().Set("Content-Type", "text/html") is constant.
_variable_arg(code) if {
	parts := regex.split(_sink_any, code)
	regex.match(`[A-Za-z_]`, parts[count(parts) - 1])
}

_variable_arg(code) if regex.match(`\(\s*$`, code)

# The code on a line: string literals and a trailing // comment removed, so a
# sink spelled inside a string is not a sink.
_code(line) := c if {
	s := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`)
	c := regex.replace(s, `//.*$`, "")
}

_is_sink(code, _, _, _) if regex.match(_sink_std, code)

_is_sink(code, lines, start, i) if {
	regex.match(_sink_gin, code)
	some k in numbers.range(start, i)
	contains(lines[k], "gin.Context")
}

_is_sink(code, lines, start, i) if {
	regex.match(_sink_fiber, code)
	some k in numbers.range(start, i)
	regex.match(`\*?fiber\.Ctx\b`, lines[k])
}

# The call's arguments: the line, plus the next lines when the call is broken
# after its parenthesis.
_args(_, _, line) := line if not regex.match(`\(\s*$`, line)

_args(lines, i, line) := a if {
	regex.match(`\(\s*$`, line)
	end := min([count(lines) - 1, i + 3])
	a := concat("\n", [lines[k] | some k in numbers.range(i, end)])
}

# The value is read inline...
_reaches(_, _, _, args, _) if regex.match(_src, args)

# ...or through a variable assigned from a source in this function (level 1),
# or from such a variable (level 2), that no later line cleans.
_reaches(_, _, _, args, vals) if {
	count(vals) > 0
	regex.match(_vals_re(vals), args)
}

_reaches(lines, start, i, args, vals) if {
	i > start
	l1 := {v |
		some j in numbers.range(start, i - 1)
		l := lines[j]
		_reads_source(l, vals)
		not helpers.is_comment_line(l)
		not regex.match(_clean, l)
		v := helpers.assigned_first(l)
	}
	count(l1) > 0
	some n in l1 | _l2(lines, start, i, l1)
	regex.match(concat("", [`\b`, n, `\b`]), args)
	not _cleaned(lines, start, i, n)
}

_reads_source(l, _) if {
	_src_gate(l)
	regex.match(_src, l)
}

_reads_source(l, vals) if {
	count(vals) > 0
	regex.match(_vals_re(vals), l)
}

# q := r.URL.Query() holds every query value: q.Get("k") and q["k"] read
# one. Passing q itself to a parser (params := parseParams(q)) does not.
_values_vars(lines, start, i) := {v |
	i > start
	some j in numbers.range(start, i - 1)
	l := lines[j]
	contains(l, ".URL.Query()")
	regex.match(`:?=\s*\w+\.URL\.Query\(\)\s*(?:$|//)`, l)
	not helpers.is_comment_line(l)
	v := helpers.assigned_first(l)
}

_vals_re(vals) := concat("", [`\b(?:`, concat("|", [v | some v in vals]), `)(?:\.Get\(|\[)`])

_l2(lines, start, i, l1) := {v |
	re := concat("", [`\b(?:`, concat("|", [n | some n in l1]), `)\b`])
	some j in numbers.range(start, i - 1)
	l := lines[j]
	regex.match(re, l)
	not helpers.is_comment_line(l)
	not regex.match(_clean, l)
	v := helpers.assigned_first(l)
}

# A line that names the variable and cleans or constrains it.
_cleaned(lines, start, i, n) if {
	some j in numbers.range(start, i - 1)
	l := lines[j]
	regex.match(concat("", [`\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
	_cleans(l, n)
}

# len() derives a new value (n := len(v)) but does not clean v: a length or
# emptiness check (if len(next) == 0 { next = "/" }) leaves it attacker-chosen.
_cleans(l, _) if regex.match(_clean_step, l)

_clean_step := replace(_clean, `|\blen\(`, "")

_cleans(l, n) if regex.match(concat("", [`\bif\b.*\w\[\s*`, n, `\s*\]`]), l)

_cleans(l, n) if regex.match(concat("", [`\bswitch\s+`, n, `\b`]), l)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_sink_gate(content)
	_src_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_any, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	_variable_arg(code)
	start := _fn_start(lines, i)
	_is_sink(code, lines, start, i)
	args := _args(lines, i, line)
	not regex.match(_clean, args)
	vals := _values_vars(lines, start, i)
	_reaches(lines, start, i, args, vals)
	finding := {
		"rule_id": metadata.id,
		"message": "A query, form or route parameter is written into a response header without neutralising it; reject or strip CR/LF and constrain the value (allow-list, url.QueryEscape, mime.FormatMediaType) before setting the header",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
