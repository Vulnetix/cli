package vulnetix.rules.vnx_java_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-013",
	"name": "Java XPath injection",
	"description": "An XPath expression is built from untrusted text and compiled or evaluated: javax.xml.xpath XPath.evaluate/compile (any receiver, in a file that uses XPath), dom4j selectNodes/selectSingleNode/createXPath and Jaxen new DOMXPath/Dom4jXPath/JDOMXPath. Reported when the expression argument (the first argument) is a servlet request value (getParameter and its wrappers, getHeader, getQueryString, getCookies), a Spring or JAX-RS annotated handler parameter, or a local assigned from one up to five assignments earlier within 40 lines; and, for repository-style code, when the expression concatenates a String parameter of the enclosing public/protected/private method into a quoted value ('\" + name + \"'), directly or through a local built a few lines above. A call that continues on the next lines is read to the end of its statement. Not reported: expressions that bind values through an XPathVariableResolver ($var), values encoded with ESAPI encodeForXPath or converted to a number, constant expressions, element names concatenated outside quotes, request data used as the document being queried rather than as the expression, Pattern.compile, and sink names in comments or string literals. Flows into another method or file are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-013/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [643],
	"capec": ["CAPEC-83"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xpath-injection", "java", "injection"],
}

_msg := "XPath expression built from untrusted input; bind the value with an XPathVariableResolver ($name in the expression) or validate it against a strict allowlist before evaluating"

# ── Sinks, each enabled by a type the file names ─────────────────────────

_sinks := [
	[`XPath`, `\.(?:evaluate|evaluateExpression|compile)\s*\(`],
	[`org\.dom4j`, `\.(?:selectNodes|selectSingleNode|createXPath|selectObject|numberValueOf)\s*\(`],
	[`org\.jaxen`, `\bnew\s+(?:DOM|Dom4j|JDOM|Base)XPath\s*\(`],
]

# ── Request taint (local) ────────────────────────────────────────────────

_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

_sanitizer_re := `encodeForXPath|Integer\.parseInt\s*\(|Integer\.valueOf\s*\(|Long\.parseLong\s*\(|Long\.valueOf\s*\(|Double\.parseDouble\s*\(`

_window := 40

_assigned(line) := v if {
	s := regex.replace(line, `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?`, "")
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*(?:\+=|=(?:[^=]|$))`, s, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

_assign_text(lines, j) := lines[j] if regex.match(`;\s*$`, lines[j])

_assign_text(lines, j) := concat(" ", [lines[k] | some k in numbers.range(j, e)]) if {
	not regex.match(`;\s*$`, lines[j])
	last := min([count(lines) - 1, j + 6])
	ends := [k | some k in numbers.range(j, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_assigns(lines, i) := [[v, _assign_text(lines, j)] |
	some j in numbers.range(max([0, i - _window]), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _assigned(lines[j])
]

_ann_names(line) := {m[2] | some m in regex.find_all_string_submatch_n(_ann_re, line, -1)}

_seeds(lines, i, assigns) := {a[0] |
	some a in assigns
	_is_src(a[1])
	not regex.match(_sanitizer_re, a[1])
} | {v |
	some j in numbers.range(max([0, i - _window]), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _ann_names(lines[j])
}

_foreach_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)`

_foreach(lines, i) := [[m[1], m[2]] |
	some j in numbers.range(max([0, i - _window]), i - 1)
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

_tainted(lines, i, assigns) := t if {
	fe := _foreach(lines, i)
	t1 := _hop(assigns, fe, _hop(assigns, fe, _seeds(lines, i, assigns)))
	t := _hop(assigns, fe, _hop(assigns, fe, _hop(assigns, fe, t1)))
}

# ── Statement and argument text ──────────────────────────────────────────

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_raw_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 4])
	ends := [k | some k in numbers.range(i, last); regex.match(`[;{]\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# The first argument of the sink call: the expression. Strings are blanked
# first so a comma or parenthesis inside the expression does not split it.
_first_arg(raw, sink) := a if {
	b := _blank(raw)
	m := regex.find_all_string_submatch_n(concat("", ["(?:", sink, ")((?:[^(),]|\\((?:[^()]|\\([^()]*\\))*\\))*)"]), b, 1)
	count(m) > 0
	a := m[0][1]
}

# The same argument with its string literals intact, for the quoted-value
# check.
_first_raw(raw, sink) := _raw_first(m[0][1]) if {
	m := regex.find_all_string_submatch_n(concat("", ["(?:", sink, ")(.*)"]), raw, 1)
	count(m) > 0
} else := ""

_raw_first(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:"(?:\\.|[^"\\])*"|[^(),"]|\((?:"(?:\\.|[^"\\])*"|[^()"]|\((?:"(?:\\.|[^"\\])*"|[^()"])*\))*\))*)`, tail, 1)
	count(m) > 0
} else := tail

_reaches(arg, _) if _is_src(arg)

_reaches(arg, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), arg)
}

# ── Method-parameter branch ──────────────────────────────────────────────

_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)+[\w.<>\[\], ?]+\s+\w+\s*\(([^)]*)`

# String parameters of the nearest method declared above line i.
_string_params(lines, i) := ps if {
	decls := [j |
		some j in numbers.range(max([0, i - 60]), i)
		regex.match(_method_re, lines[j])
	]
	count(decls) > 0
	d := max(decls)
	m := regex.find_all_string_submatch_n(_method_re, lines[d], 1)
	ps := {p[1] | some p in regex.find_all_string_submatch_n(`(?:final\s+)?(?:@\w+(?:\([^)]*\))?\s+)*String\s+(\w+)`, m[0][1], -1)}
}

# Idents concatenated into a quoted value: '" + name
_quoted_concats(s) := {m[1] | some m in regex.find_all_string_submatch_n(`'\s*"\s*\+\s*(\w+)`, s, -1)}

# The expression's own text plus the assignments of the locals it names.
_expr_text(raw_first, assigns) := concat(" ", array.concat([raw_first], [a[1] |
	some a in assigns
	regex.match(concat("", [`\b`, a[0], `\b`]), regex.replace(raw_first, `"(?:\\.|[^"\\])*"`, `""`))
]))

_param_concat(lines, i, raw_first, assigns) if {
	ps := _string_params(lines, i)
	count(ps) > 0
	txt := _expr_text(raw_first, assigns)
	not regex.match(_sanitizer_re, txt)
	some v in _quoted_concats(txt)
	v in ps
}

_vulnerable(_, _, arg, _, _, t) if {
	not regex.match(_sanitizer_re, arg)
	_reaches(arg, t)
}

_vulnerable(lines, i, _, raw_first, assigns, _) if _param_concat(lines, i, raw_first, assigns)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	some s in _sinks
	regex.match(s[0], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	not regex.match(`\bPattern\s*\.\s*compile\s*\(`, line)
	regex.match(s[1], _blank(line))
	raw := _raw_stmt(lines, i)
	arg := _first_arg(raw, s[1])
	raw_first := _first_raw(raw, s[1])
	assigns := _assigns(lines, i)
	t := _tainted(lines, i, assigns)
	_vulnerable(lines, i, arg, raw_first, assigns, t)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
