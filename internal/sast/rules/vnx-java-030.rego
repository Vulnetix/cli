package vulnetix.rules.vnx_java_030

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-030",
	"name": "Java reflected cross-site scripting",
	"description": "HTTP request data is written into an HTML response without output encoding: response.getWriter() or a PrintWriter/JspWriter/ServletOutputStream local (print, println, write, printf, format, append), response.getOutputStream().write, a JSP scriptlet expression <%= %> or out.print, or a value returned from a Spring @ResponseBody / @RestController method or ResponseEntity whose content type is text/html. The value is a servlet request value (getParameter and its wrappers, getParameterValues/getParameterMap, getHeader/getHeaders, getQueryString, getPathInfo, getRequestURI/getRequestURL, getCookies and a cookie's getValue), a Spring or JAX-RS annotated handler parameter (@RequestParam, @PathVariable, @RequestHeader, @CookieValue, @RequestBody, @ModelAttribute, @QueryParam, @PathParam, @FormParam, @HeaderParam), or a local assigned from one up to twelve assignments (or a for-each over one) earlier within the enclosing method (at most 120 lines up). A call or assignment that continues on the next lines is read to the end of its statement. Before reporting, the enclosing method is read: definitions on a branch that a constant condition never takes are dropped; a local that provably holds a constant at the call (a literal, the element a list index or map key holds, the result of a same-file method whose every return is constant) stops carrying the request value; a request value stored in a list, map or builder and read back is followed; a call handed only constants on a constant receiver is inert. A value the analysis cannot resolve stays reported. Not reported: a value passed through an HTML, attribute or script encoder (ESAPI encodeForHTML/encodeForHTMLAttribute/encodeForJavaScript, OWASP Encoder Encode.forHtml*/forJavaScript*, StringEscapeUtils.escapeHtml3/4 and escapeXml*, HtmlUtils.htmlEscape, Jsoup.clean, Apache Commons Text, Spring utilities, any escape*/sanitize* call), a number or boolean parsed from the value (Integer.parseInt and the like), a constant, a response whose content type is not HTML (application/json, text/plain, text/xml, octet-stream and so on), the length of a value, comments, sink names inside string literals and test files. Flows into another file, and into another method except a same-file method whose every return is constant, are not followed. Calls into other classes of the project are read from that class's own source (a method summary one level deep, overloads told apart by arity, an interface or base type joined over its project subclasses): a call whose every return is constant is constant, a call that returns a function of its arguments or of the constructor argument its receiver was built with is exactly as tainted as that argument, and an opaque method (it reads a request value, or a field a setter changes), a simple class name declared by two files, a class outside the project or a type with an anonymous subclass stays reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-030/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "servlet", "injection", "output-encoding"],
}

# ── Request taint (local) ────────────────────────────────────────────────

_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getRequestURL|getServletPath|getCookies)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

_gate_re := `(?m)(\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getRequestURL|getServletPath|getCookies)\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b)`

# Anything that makes the value safe in HTML, or not text: an output encoder,
# a sanitiser, a numeric or boolean conversion, a length.
_sanitizer_re := `[eE]ncodeFor\w+|\bEncode\.for\w+|[eE]scape\w*\s*\(|\bhtmlEscape\w*|\bJsoup\.clean|\bHtmlUtils\b|\bStringEscapeUtils\b|\b[sS]anitiz\w*\s*\(|\bHtmlSanitizer|\bPolicyFactory|\bAntiSamy|\bInteger\.(?:parseInt|valueOf)\s*\(|\bLong\.(?:parseLong|valueOf)\s*\(|\b(?:Double|Float|Short|Byte)\.(?:parse\w+|valueOf)\s*\(|\bBoolean\.(?:parseBoolean|valueOf)\s*\(|\bUUID\.|\bURLEncoder\.encode|\b[A-Z][A-Z0-9_]{2,}\s*\.\s*get(?:OrDefault)?\s*\(`

# The name a statement assigns, after an optional `if (...)` or `else` on the
# same line: `if (values != null) param = values[0];`.
_assigned(line) := v if {
	s := regex.replace(line, `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?`, "")
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*(?:\+=|=(?:[^=]|$))`, s, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

# An assignment's whole statement, to its `;`, at most six lines, so that
# `value =\n    new String(decode(param))` is read as one.
_assign_text(lines, j) := lines[j] if regex.match(`;\s*$`, lines[j])

_assign_text(lines, j) := concat(" ", [lines[k] | some k in numbers.range(j, e)]) if {
	not regex.match(`;\s*$`, lines[j])
	last := min([count(lines) - 1, j + 6])
	ends := [k | some k in numbers.range(j, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# [name, statement text] for every assignment in the window above line i.
_assigns(lines, i) := [[v, _assign_text(lines, j)] |
	some j in helpers.span(_wstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _assigned(lines[j])
	not regex.match(_san(lines), _assign_text(lines, j))
]

# Same-file methods that encode what they are handed: a wrapper such as
# `String safe = clean(param)` is as good as the encoder it calls.
_decl_re := `^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)+[\w<>\[\].,? ]+\s+(\w+)\s*\(`

_enc_re := `[eE]ncodeFor\w+|\bEncode\.for\w+|\bescapeHtml\w*|\bescapeXml\w*|\bescapeEcmaScript|\bescapeJavaScript|\bhtmlEscape\w*|\bJsoup\.clean|\bHtmlUtils\b|\bStringEscapeUtils\b|\b[sS]anitiz\w*\s*\(`

# A declaration without modifiers has its whole signature on one line.
_decl_re2 := `^\s*([\w<>\[\].,?]+)\s+(\w+)\s*\([^;=]*\)\s*(?:throws[\w., ]*)?\{\s*$`

_decls(lines) := array.concat([[j, m[0][1]] |
	some j, l in lines
	contains(l, "(")
	m := regex.find_all_string_submatch_n(_decl_re, l, 1)
	count(m) > 0
], [[j, m[0][2]] |
	some j, l in lines
	contains(l, "(")
	m := regex.find_all_string_submatch_n(_decl_re2, l, 1)
	count(m) > 0
	not m[0][1] in {"return", "new", "else", "throw", "case"}
	not m[0][2] in {"if", "for", "while", "switch", "catch", "synchronized"}
])

# Names whose most recent unconditional assignment before line i went through
# an encoder: `name = HtmlUtils.htmlEscape(name);`.
_cleansed(lines, i) := {v |
	some j in helpers.span(_wstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	not regex.match(`^\s*(?:\}\s*)?(?:else|if)\b`, lines[j])
	v := _assigned(lines[j])
	regex.match(_san(lines), _assign_text(lines, j))
	not _reassigned(lines, j, i, v)
	_balance(lines, j, i) >= 0
}

# Braces opened minus closed from line j up to line i: negative when the
# assignment sat in a block that closed before i, so it only ran sometimes.
_balance(lines, j, i) := sum([d | some k in helpers.span(j, i - 1); d := _delta(lines[k])])

_delta(l) := count(regex.find_n(`\{`, l, -1)) - count(regex.find_n(`\}`, l, -1))

_reassigned(lines, j, i, v) if {
	some k in helpers.span(j + 1, i - 1)
	not helpers.is_comment_line(lines[k])
	_assigned(lines[k]) == v
}

_enc_methods(lines) := {d[1] |
	ds := _decls(lines)
	some d in ds
	e := min(array.concat([count(lines)], [x[0] | some x in ds; x[0] > d[0]]))
	regex.match(_enc_re, concat(" ", array.slice(lines, d[0] + 1, e)))
}

_san(lines) := concat("", [_sanitizer_re, `|\b(?:`, concat("|", _enc_methods(lines)), `)\s*\(`]) if count(_enc_methods(lines)) > 0

_san(lines) := _sanitizer_re if count(_enc_methods(lines)) == 0

# An annotated parameter of a stream or multipart type is content; its
# getOriginalFilename() is caught as a source call instead.
_ann_names(line) := {m[2] |
	some m in regex.find_all_string_submatch_n(_ann_re, line, -1)
	not m[1] in {"MultipartFile", "InputStream", "Part", "byte", "Resource", "int", "long", "Integer", "Long", "boolean", "Boolean", "double", "float", "short"}
}

_seeds(lines, i, assigns) := {a[0] |
	some a in assigns
	_is_src(a[1])
	not regex.match(_sanitizer_re, a[1])
} | {v |
	some j in helpers.span(_wstart(lines, i), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _ann_names(lines[j])
} | {m[1] |
	# for (Cookie c : req.getCookies()) makes c request data.
	some j in helpers.span(_wstart(lines, i), i - 1)
	contains(lines[j], "for")
	some m in regex.find_all_string_submatch_n(_foreach_src_re, lines[j], 1)
	_is_src(m[2])
}

_foreach_src_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*([^;]*\))\s*\)`

# for (Cookie c : cookies) carries the taint of cookies to c.
_foreach_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)`

_foreach(lines, i) := [[m[1], m[2]] |
	some j in helpers.span(_wstart(lines, i), i - 1)
	contains(lines[j], "for")
	some m in regex.find_all_string_submatch_n(_foreach_re, lines[j], 1)
]

_hop(_, _, t) := t if count(t) == 0

_hop(assigns, fe, t) := (t | {a[0] |
	some a in assigns
	regex.match(re, a[1])
	not regex.match(_sanitizer_re, a[1])
}) | {p[0] | some p in fe; p[1] in t} if {
	count(t) > 0
	re := concat("", [`\b(?:`, concat("|", t), `)\b`])
}

_hop4(assigns, fe, t) := _hop(assigns, fe, _hop(assigns, fe, _hop(assigns, fe, _hop(assigns, fe, t))))

# Names holding request data at line i: assigned from a source, an annotated
# handler parameter, or up to twelve assignments away from one (a chain of
# propagators a test or a long sanitising pipeline strings together).
_tainted(lines, i) := t if {
	assigns := _assigns(lines, i)
	fe := _foreach(lines, i)
	t := _hop4(assigns, fe, _hop4(assigns, fe, _hop4(assigns, fe, _seeds(lines, i, assigns)))) - _cleansed(lines, i)
}

# ── Statement and argument text ──────────────────────────────────────────

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_stmt(lines, i) := concat(" ", [_blank(lines[k]) | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 10])
	ends := [k | some k in numbers.range(i, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_balanced(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)\)`, tail, 1)
	count(m) > 0
} else := tail

# ── Sinks ────────────────────────────────────────────────────────────────

_print_re := `\.\s*(?:print|println|write|printf|format|append)\s*\(`

# Names of response writers and streams in the file.
_writers(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(?:JspWriter|ServletOutputStream)\s+(\w+)`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\bPrintWriter\s+(\w+)\s*[,)]`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*[\w.()]*\.(?:getWriter|getOutputStream)\s*\(`, content, -1)
}

_writer_line(line, ws) if regex.match(`getWriter\s*\(|getOutputStream\s*\(`, line)

_writer_line(line, ws) if {
	some w in ws
	regex.match(concat("", [`\b`, w, `\s*(?:\.\s*append\s*\([^()]*\))?\s*`, _print_re]), line)
}
_print_args(stmt) := [a |
	some m in regex.find_all_string_submatch_n(concat("", [_print_re, `(.*)`]), stmt, -1)
	a := m[1]
]

# A JSP scriptlet expression.
_jsp_args(stmt) := [trim_space(m[1]) | some m in regex.find_all_string_submatch_n(`<%=(.*?)%>`, stmt, -1)]

# Spring: a returned value or ResponseEntity body of a method that produces HTML.
_ret_re := `^\s*return\s+(.*)$`

_spring_args(lines, i) := [a |
	not regex.match(`\b(?:getWriter|getOutputStream)\b`, lines[i])
	m := regex.find_all_string_submatch_n(_ret_re, _stmt(lines, i), 1)
	count(m) > 0
	_html_method(lines, i)
	a := m[0][1]
]

_html_markers := `(?:produces\s*=[^)]*(?:text/html|TEXT_HTML)|MediaType\.TEXT_HTML|TEXT_HTML_VALUE|"text/html|contentType\s*\(\s*MediaType\.TEXT_HTML)`

_html_method(lines, i) if {
	s := max([0, helpers.flow_method_start(lines, i) - 8])
	win := concat("\n", [lines[k] | some k in numbers.range(s, i)])
	regex.match(_html_markers, win)
	regex.match(`@ResponseBody|@RestController|ResponseEntity`, win)
}

_html_method(lines, i) if {
	s := max([0, helpers.flow_method_start(lines, i) - 8])
	regex.match(_html_markers, concat("\n", [lines[k] | some k in numbers.range(s, i)]))
	regex.match(`@RestController`, concat("\n", lines))
}

# A response whose content type is declared not HTML before the sink.
_non_html(lines, i) if {
	s := _wstart(lines, i)
	some k in numbers.range(s, i)
	not helpers.is_comment_line(lines[k])
	regex.match(`(?i)(?:setContentType|setHeader|addHeader)\s*\(\s*(?:"Content-Type"\s*,\s*)?"(?:application/|text/(?:plain|xml|csv|javascript|css)|image/|audio/|video/)`, lines[k])
}

_non_html(lines, i) if {
	s := _wstart(lines, i)
	some k in numbers.range(s, i)
	not helpers.is_comment_line(lines[k])
	regex.match(`MediaType\.(?:APPLICATION_\w+|TEXT_PLAIN|TEXT_XML)|produces\s*=\s*\{?\s*"(?:application/|text/plain)`, lines[k])
}

_refs(args, t) := {v | some v in t; regex.match(concat("", [`\b`, v, `\b`]), args)}

_reaches(args, _) if _is_src(args)

_reaches(args, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_gate_re, content)
	ws := _writers(content)
	lines := split(content, "\n")
	some i, line in lines
	_hit(lines, i, line, ws)
	not _continuation_of_hit(lines, i, ws)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".jsp")
	not helpers.is_test_path(path)
	not regex.match(`contentType\s*=\s*"(?:application/|text/plain|text/xml)`, content)
	regex.match(`request\.|@RequestParam`, content)
	lines := split(content, "\n")
	some i, line in lines
	_jsp_hit(lines, i, line)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "HTTP request data is written into an HTML response without output encoding; encode it for the context it lands in (OWASP Encoder Encode.forHtml, ESAPI encodeForHTML, HtmlUtils.htmlEscape) or use a template engine that escapes by default",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_continuation_of_hit(lines, i, ws) if {
	i > 0
	prev := lines[i - 1]
	not regex.match(`[;{}]\s*$`, prev)
	_hit(lines, i - 1, prev, ws)
}

_hit(lines, i, line, ws) if {
	not helpers.is_comment_line(line)
	_writer_line(_blank(line), ws)
	stmt := _stmt(lines, i)
	some args in _print_args(stmt)
	_tainted_args(lines, i, args)
	not _non_html(lines, i)
}

_hit(lines, i, line, _) if {
	not helpers.is_comment_line(line)
	regex.match(`^\s*return\s`, line)
	some args in _spring_args(lines, i)
	_tainted_args(lines, i, args)
	not _non_html(lines, i)
}

_hit(lines, i, line, _) if {
	not helpers.is_comment_line(line)
	regex.match(`ResponseEntity\s*\.\s*ok\s*\(|\.body\s*\(`, _blank(line))
	_html_method(lines, i)
	m := regex.find_all_string_submatch_n(`(?:ResponseEntity\s*\.\s*ok|\.body)\s*\((.*)`, _stmt(lines, i), 1)
	count(m) > 0
	_tainted_args(lines, i, _balanced(m[0][1]))
	not _non_html(lines, i)
}

_jsp_hit(lines, i, line) if {
	regex.match(`<%=`, line)
	some args in _jsp_args(_stmt(lines, i))
	_tainted_args(lines, i, args)
}

_jsp_hit(lines, i, line) if {
	not helpers.is_comment_line(line)
	regex.match(`\bout\s*\.\s*(?:print|println|write|append)\s*\(`, line)
	some args in _print_args(_stmt(lines, i))
	_tainted_args(lines, i, args)
}

_tainted_args(lines, i, args) if {
	not regex.match(_san(lines), args)
	t := _tainted(lines, i)
	_reach_live(lines, i, args, t)
}

# ── In-method flow ───────────────────────────────────────────────────────

_live(_, _, args) if _is_src(args)

_live(lines, i, args) if {
	not _is_src(args)
	seeds := _seeds(lines, i, _assigns(lines, i)) | helpers.flow_carrier_seeds(lines, i, _src_re)
	helpers.flow_reaches(lines, i, args, seeds - _cleansed(lines, i), _san(lines))
}

_reach_live(lines, i, args, t) if {
	_reaches(args, t)
	_live(lines, i, args)
}

_reach_live(lines, i, args, t) if {
	not _reaches(args, t)
	_any_seed(lines, i, t)
	_live(lines, i, args)
}

_wstart(lines, i) := max([0, helpers.flow_method_start(lines, i) - 1])

_any_seed(_, _, t) if count(t) > 0

_any_seed(lines, i, t) if {
	count(t) == 0
	count(helpers.flow_carrier_seeds(lines, i, _src_re)) > 0
}
