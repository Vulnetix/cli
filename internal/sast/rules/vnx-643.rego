# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_643

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-643",
	"name": "XPath injection: query built from a dynamic string",
	"description": "An XPath query is built by splicing a variable into the expression text and then compiled or evaluated, so a value such as ' or '1'='1 rewrites the query (CWE-643). Reported in Java: javax.xml.xpath XPath.compile()/evaluate() on an XPath receiver (a variable declared as XPath, or named xpath/xp) and dom4j selectNodes()/selectSingleNode()/selectObject()/createXPath(); in Python: lxml .xpath() and etree.XPath(), elementpath.select()/iter_select(), and ElementTree find()/findall()/iterfind()/findtext() when the path has an XPath predicate. The expression argument (also when it starts on the next line) must be concatenation of a literal with a non-constant value, String.format/formatted/MessageFormat.format, a Python f-string with a placeholder, %-formatting or .format(), an io.StringIO buffer that a non-constant value is written into with write() and read back with getvalue(), or a variable assigned from such an expression up to 20 lines above. The enclosing method or function (at most 120 lines up) is read first, and an operand that provably holds a constant at the call is not spliced data: a literal it was last assigned on every live path, the taken side of an if/else (Python if/elif/else) or conditional expression whose condition folds to a constant (integer literals and int locals assigned once; in Python also a literal tested with in/not in against a string local), the selected case of a switch or match on a constant, the element a list index or map, dict or ConfigParser key actually holds when that is a literal, and the result of a same-file method or function (including a nested class) whose every return is constant. In Python, inside an apostrophe-quoted XPath literal, a value whose apostrophes are replaced (.replace(\"'\", ...)) or that an early return has proven free of them (if \"'\" in v: return) is not reported either. A value the analysis cannot resolve (a condition on run-time data, a call into another file, a collection passed elsewhere, a try block, a loop) stays reported. A call into code the analysis cannot see is read as inert, and its value is constant, when it is not named like a source (read*, input, getenv, get_*param/header/cookie/value, query, execute, popen), every argument is a constant, and its receiver is a class, an imported module, or a local built from such a call or from a constructor with constant arguments that is only ever called with constant arguments; a call handed a run-time argument, made on a run-time receiver or named like a source stays reported. Not reported: constant expressions (literals, ALL_CAPS constants), a single numeric %-conversion (\"%d\" % int(x)), parameterised queries (XPathVariableResolver, lxml $name variables bound by keyword), other evaluate() receivers (ScriptEngine, browser document.evaluate), comments and string literals. A Java expression traced to request data (a servlet parameter, header or cookie, an annotated handler parameter, or a String method parameter spliced into a quoted value) is reported by VNX-JAVA-013, the Java taint rule for the same injection, so the line is reported once; this rule keeps the Java expressions built from other non-constant values. Whether a non-constant value is attacker-controlled is not judged. A call chain of constant operands nested up to four deep (new String(decode(encode(name.getBytes())))) is folded as constant.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-643/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [643],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xpath-injection", "injection", "cwe-643"],
}

# ── Is an expression text built dynamically? ─────────────────────────────

_const(id) if regex.match(`^[A-Z][A-Z0-9_]*$`, id)

# A literal left where a constant operand was folded.
_const(id) if regex.match(`^(?:""|''|-?\d+)$`, id)

# A literal concatenated with a non-constant operand, on either side.
_built(s, _) if {
	some m in regex.find_all_string_submatch_n(`["']\s*\+\s*([A-Za-z_][\w.]*)`, s, -1)
	not _const(m[1])
}

_built(s, _) if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+\s*["']`, s, -1)
	not _const(m[1])
}

_built(s, "java") if regex.match(`\bString\.format\(|\.formatted\(|\bMessageFormat\.format\(|"\s*\)?\s*\.concat\(`, s)

# f-string with a placeholder that is not only constants.
_built(s, "py") if {
	some m in regex.find_all_string_submatch_n(`\b(?:[fF][rR]?|[rR][fF])("|')(?:\\.|[^\\])*?\{([^{}]+)\}`, s, -1)
	not _const(trim_space(m[2]))
}

_built(s, "py") if {
	regex.match(`["']\s*%\s*[\w(\[]`, s)
	# A single numeric conversion ("%d" % int(x)) cannot carry XPath syntax.
	not regex.match(`["']\s*%\s*(?:int|float|len)\([^()]*\)\s*\)?\s*$`, s)
}

_built(s, "py") if regex.match(`["']\s*\.format\(`, s)

# "".join(['/a[@id=\'', value, '\']']): a list with a bare name in it.
_built(s, "py") if regex.match(`["']\s*\.join\(\s*\[[^\]]*,\s*[a-z_]\w*\s*,`, s)

# ── Sinks: the expression argument text ──────────────────────────────────

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_gate("java", c) if regex.match(`XPath|selectNodes|selectSingleNode|selectObject|createXPath`, c)

_gate("py", c) if regex.match(`xpath|XPath|elementpath|ElementTree|etree`, c)

# Java XPath receiver: declared XPath in the file, or named after it.
_java_xpath_recv(_, r) if regex.match(`(?i)^(?:xp|\w*xpath\w*)$`, r)

_java_xpath_recv(content, r) if regex.match(concat("", [`\bXPath\s+`, r, `\b`]), content)

_sink(content, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\b(\w+)\.(?:compile|evaluate)\(\s*(.*)$`, line, 1)
	count(m) > 0
	_java_xpath_recv(content, m[0][1])
	rest := m[0][2]
}

_sink(_, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\bnewXPath\(\)\s*\.(?:compile|evaluate)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(_, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\.(?:selectNodes|selectSingleNode|selectObject|createXPath)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(_, line, "py") := rest if {
	m := regex.find_all_string_submatch_n(`(?:\.xpath|\bXPath)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

# elementpath.select(root, path): the path is the second argument.
_sink(_, line, "py") := rest if {
	m := regex.find_all_string_submatch_n(`\belementpath\.(?:select|iter_select|Selector)\(\s*(?:[\w.]+\s*,\s*)?(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(content, line, "py") := rest if {
	regex.match(`ElementTree|etree`, content)
	m := regex.find_all_string_submatch_n(`\.(?:find|findall|iterfind|findtext)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
	regex.match(`\[\s*@|\[[\w.-]+\s*=`, rest)
}

# The argument text: the rest of the sink line, or the next code line when
# the call breaks right after its opening parenthesis.
_arg(_, _, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := lines[j] if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 2)
}

# A bare variable passed as the expression, built a few lines above.
_var_built(lines, i, arg, lang, C) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, arg, 1)
	count(m) > 0
	v := m[0][1]
	re := concat("", [`^\s*(?:(?:final\s+)?[\w<>\[\]]+\s+)?`, v, `\s*=[^=]`])
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(re, lines[j])
	not helpers.is_comment_line(lines[j])
	_built(_fold(lines, lines[j], j, C, lang), lang)
}

# An io.StringIO assembled with write() and read back with getvalue():
#   buf = io.StringIO(); buf.write("/a[@id='"); buf.write(v); q = buf.getvalue()
# is the same splice as concatenation when one write is not a constant.
_var_built(lines, i, arg, "py", C) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, arg, 1)
	count(m) > 0
	v := m[0][1]
	re := concat("", [`^\s*`, v, `\s*=\s*([A-Za-z_]\w*)\.getvalue\(\s*\)\s*$`])
	some j in helpers.span(max([0, i - 20]), i - 1)
	g := regex.find_all_string_submatch_n(re, lines[j], 1)
	count(g) > 0
	b := g[0][1]
	ctor := concat("", [`^\s*`, b, `\s*=\s*(?:io\.)?StringIO\(`])
	some c in helpers.span(max([0, j - 25]), j - 1)
	regex.match(ctor, lines[c])
	some k in helpers.span(c + 1, j - 1)
	w := regex.find_all_string_submatch_n(concat("", [`^\s*`, b, `\.write\(\s*(.*?)\s*\)\s*$`]), _fold(lines, lines[k], k, C, "py"), 1)
	count(w) > 0
	_sio_dynamic(w[0][1])
}

_sio_dynamic(a) if _built(a, "py")

_sio_dynamic(a) if {
	regex.match(`^[A-Za-z_][\w.]*(?:\([^()]*\))?$`, a)
	not _const(a)
}

# The method is read first: operands that provably hold a constant at the
# call (helpers.flow_consts / flow_py_consts) are folded to "" before the
# "is it built dynamically?" test.
_consts(lines, i, "java") := helpers.flow_consts(lines, i)

_consts(lines, i, "py") := helpers.flow_py_consts(lines, i)

_fold(_, text, line, C, "java") := helpers.flow_fold(text, line, C)

_fold(lines, text, line, C, "py") := helpers.flow_py_fold(_quote_safe(lines, text, line), line, C)

# ── Apostrophe-quoted literals ───────────────────────────────────────────
# Inside an XPath literal delimited by apostrophes ('...' or \'...\' in the
# Python source), a value whose apostrophes are replaced, or one an early
# return has proven free of them, cannot close the literal, so it splices
# no syntax. Only that delimiter is trusted: a value placed between double
# quotes, or concatenated anywhere else, stays reported.

_rep_apos := `\.\s*replace\(\s*(?:'\\''|"'")\s*,\s*(?:'[^'{}]*'|"[^"{}]*")\s*\)`

_quote_safe(lines, text, line) := _guard_fold(t2, _apos_free(lines, line)) if {
	t1 := regex.replace(text, concat("", [`(\\?')\{\s*[A-Za-z_][\w.]*\s*`, _rep_apos, `\s*\}`]), "${1}{0}")
	t2 := regex.replace(t1, concat("", [`(\\''|'")(\s*\+\s*)[A-Za-z_][\w.]*\s*`, _rep_apos]), `${1}${2}""`)
}

_guard_fold(t, g) := t if count(g) == 0

_guard_fold(t, g) := t2 if {
	count(g) > 0
	alt := concat("|", g)
	t1 := regex.replace(t, concat("", [`(\\?')\{\s*(?:`, alt, `)\s*\}`]), "${1}{0}")
	t2 := regex.replace(t1, concat("", [`(\\''|'")(\s*\+\s*)(?:`, alt, `)\b`]), `${1}${2}""`)
}

# Names checked by `if "'" in name:` with a block that returns or raises,
# in a block enclosing `i`, and not rebound before it.
_apos_free(lines, i) := {v |
	some g in numbers.range(max([0, i - 60]), i - 1)
	g < i
	contains(lines[g], " in ")
	m := regex.find_all_string_submatch_n(`^\s*if\s+(?:'\\''|"'")\s+in\s+([A-Za-z_]\w*)\s*:\s*(?:#.*)?$`, lines[g], 1)
	count(m) > 0
	v := m[0][1]
	_exits(lines, g)
	_encloses(lines, g, i)
	not _rebound(lines, g, i, v)
}

_ind(l) := count(l) - count(trim_left(l, " \t"))

_exits(lines, g) if {
	d := _ind(lines[g])
	ks := [k | some k in numbers.range(g + 1, min([count(lines) - 1, g + 12])); k > g; trim_space(lines[k]) != ""]
	count(ks) > 0
	bd := _ind(lines[ks[0]])
	bd > d
	e := min(array.concat([k | some k in ks; _ind(lines[k]) <= d], [g + 13]))
	some k in ks
	k < e
	_ind(lines[k]) == bd
	regex.match(`^\s*(?:return|raise)\b`, lines[k])
}

_encloses(lines, g, i) if {
	d := _ind(lines[g])
	every k in numbers.range(g + 1, i) {
		_at_least(lines[k], d)
	}
}

_at_least(l, _) if trim_space(l) == ""

_at_least(l, _) if startswith(trim_space(l), "#")

_at_least(l, d) if _ind(l) >= d

_rebound(lines, g, i, v) if {
	some k in helpers.span(g + 1, i - 1)
	k < i
	regex.match(concat("", [`^\s*`, v, `\s*(?::[^=]+)?(?:[-+*/%|&^]|//)?=(?:[^=]|$)|\bfor\s+.*\b`, v, `\b.*\bin\b|\bas\s+`, v, `\b`]), lines[k])
}

_tainted(lines, i, arg, lang) if {
	C := _consts(lines, i, lang)
	_tainted_c(lines, i, _fold(lines, arg, i, C, lang), lang, C)
}

_tainted_c(_, _, arg, lang, _) if _built(arg, lang)

_tainted_c(lines, i, arg, lang, C) if _var_built(lines, i, arg, lang, C)

# Python prose: a line that opens with a quote or sits in a docstring.
_prose(lines, i, "py") if regex.match(`^\s*[rbuf]?("|')`, lines[i])

_prose(lines, i, "py") if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
	n % 2 == 1
}

# The sink call itself sits inside a string literal.
_in_literal(line) if regex.match(`^[^"']*"[^"]*(?:\.xpath|XPath|evaluate|compile|select\w*|find\w*)\(`, line)

_in_literal(line) if regex.match(`^\s*\w+\s*=\s*["']`, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)xpath|evaluate\(|compile\(|select\w*\(|find\w*\(`, line)
	not helpers.is_comment_line(line)
	rest := _sink(content, line, lang)
	not _in_literal(line)
	arg := _arg(lines, i, rest)
	_tainted(lines, i, arg, lang)
	not _prose(lines, i, lang)
	not _java_013_owns(lang, content, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "XPath query built from a dynamic string: a value spliced into the expression can rewrite the query. Bind it as an XPath variable (XPathVariableResolver, lxml $name keyword arguments) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Java lines VNX-JAVA-013 reports ───────────────────────────────────────
# A Java XPath expression that VNX-JAVA-013 traces to request data (a servlet
# parameter, header or cookie, an annotated handler parameter, or a DAO
# String parameter in a quoted value) is the same injection with a confirmed
# source, and VNX-JAVA-013 reports that line. The conditions below are
# VNX-JAVA-013's own findings conditions, copied with a _j13_ prefix so this
# rule only stays quiet on a line that rule does report. Keep them in step.
# It is evaluated only for a line this rule would otherwise report.

_java_013_owns("java", content, lines, i, line) if _reported_by_java_013(content, lines, i, line)
# ── Sinks, each enabled by a type the file names ─────────────────────────

_j13_sinks := [
	[`XPath`, `\.(?:evaluate|evaluateExpression|compile)\s*\(`],
	[`org\.dom4j`, `\.(?:selectNodes|selectSingleNode|createXPath|selectObject|numberValueOf)\s*\(`],
	[`org\.jaxen`, `\bnew\s+(?:DOM|Dom4j|JDOM|Base)XPath\s*\(`],
]

# ── Request taint (local) ────────────────────────────────────────────────

_j13_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_j13_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_j13_is_src(s) if {
	regex.match(_j13_src_re, s)
	regex.match(_j13_src_re, regex.replace(s, _j13_not_src_re, ""))
}

_j13_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

_j13_sanitizer_re := `encodeForXPath|Integer\.parseInt\s*\(|Integer\.valueOf\s*\(|Long\.parseLong\s*\(|Long\.valueOf\s*\(|Double\.parseDouble\s*\(`


_j13_assigned(line) := v if {
	s := regex.replace(line, `^\s*(?:\}\s*)?(?:else\s+)?(?:if\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*)?`, "")
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*(?:\+=|=(?:[^=]|$))`, s, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

_j13_assign_text(lines, j) := lines[j] if regex.match(`;\s*$`, lines[j])

_j13_assign_text(lines, j) := concat(" ", [lines[k] | some k in numbers.range(j, e)]) if {
	not regex.match(`;\s*$`, lines[j])
	last := min([count(lines) - 1, j + 6])
	ends := [k | some k in numbers.range(j, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_j13_assigns(lines, i) := [[v, _j13_assign_text(lines, j)] |
	some j in numbers.range(_j13_wstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _j13_assigned(lines[j])
]

_j13_ann_names(line) := {m[2] | some m in regex.find_all_string_submatch_n(_j13_ann_re, line, -1)}

_j13_seeds(lines, i, assigns) := {a[0] |
	some a in assigns
	_j13_is_src(a[1])
	not regex.match(_j13_sanitizer_re, a[1])
} | {v |
	some j in numbers.range(_j13_wstart(lines, i), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _j13_ann_names(lines[j])
} | {m[1] |
	# for (Cookie c : req.getCookies()) makes c request data.
	some j in numbers.range(_j13_wstart(lines, i), i - 1)
	contains(lines[j], "for")
	some m in regex.find_all_string_submatch_n(_j13_foreach_src_re, lines[j], 1)
	_j13_is_src(m[2])
}

_j13_foreach_src_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*([^;]*\))\s*\)`

_j13_foreach_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)`

_j13_foreach(lines, i) := [[m[1], m[2]] |
	some j in numbers.range(_j13_wstart(lines, i), i - 1)
	contains(lines[j], "for")
	some m in regex.find_all_string_submatch_n(_j13_foreach_re, lines[j], 1)
]

_j13_hop(_, _, t) := t if count(t) == 0

_j13_hop(assigns, fe, t) := (t | {a[0] |
	some a in assigns
	regex.match(re, a[1])
	not regex.match(_j13_sanitizer_re, a[1])
}) | {p[0] | some p in fe; p[1] in t} if {
	count(t) > 0
	re := concat("", [`\b(?:`, concat("|", t), `)\b`])
}

_j13_tainted(lines, i, assigns) := t if {
	fe := _j13_foreach(lines, i)
	t1 := _j13_hop(assigns, fe, _j13_hop(assigns, fe, _j13_seeds(lines, i, assigns)))
	t := _j13_hop(assigns, fe, _j13_hop(assigns, fe, _j13_hop(assigns, fe, t1)))
}

# ── Statement and argument text ──────────────────────────────────────────

_j13_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_j13_raw_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 4])
	ends := [k | some k in numbers.range(i, last); regex.match(`[;{]\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# The first argument of the sink call: the expression. Strings are blanked
# first so a comma or parenthesis inside the expression does not split it.
_j13_first_arg(raw, sink) := a if {
	b := _j13_blank(raw)
	m := regex.find_all_string_submatch_n(concat("", ["(?:", sink, ")((?:[^(),]|\\((?:[^()]|\\([^()]*\\))*\\))*)"]), b, 1)
	count(m) > 0
	a := m[0][1]
}

# The same argument with its string literals intact, for the quoted-value
# check.
_j13_first_raw(raw, sink) := _j13_raw_first(m[0][1]) if {
	m := regex.find_all_string_submatch_n(concat("", ["(?:", sink, ")(.*)"]), raw, 1)
	count(m) > 0
} else := ""

_j13_raw_first(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:"(?:\\.|[^"\\])*"|[^(),"]|\((?:"(?:\\.|[^"\\])*"|[^()"]|\((?:"(?:\\.|[^"\\])*"|[^()"])*\))*\))*)`, tail, 1)
	count(m) > 0
} else := tail

_j13_reaches(arg, _) if _j13_is_src(arg)

_j13_reaches(arg, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), arg)
}

# ── Method-parameter branch ──────────────────────────────────────────────

_j13_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)+[\w.<>\[\], ?]+\s+\w+\s*\(([^)]*)`

# String parameters of the nearest method declared above line i.
_j13_string_params(lines, i) := ps if {
	decls := [j |
		some j in numbers.range(max([0, i - 60]), i)
		regex.match(_j13_method_re, lines[j])
	]
	count(decls) > 0
	d := max(decls)
	m := regex.find_all_string_submatch_n(_j13_method_re, lines[d], 1)
	ps := {p[1] | some p in regex.find_all_string_submatch_n(`(?:final\s+)?(?:@\w+(?:\([^)]*\))?\s+)*String\s+(\w+)`, m[0][1], -1)}
}

# Idents concatenated into a quoted value: '" + name
_j13_quoted_concats(s) := {m[1] | some m in regex.find_all_string_submatch_n(`'\s*"\s*\+\s*(\w+)`, s, -1)}

# The expression's own text plus the assignments of the locals it names.
_j13_expr_text(raw_first, assigns) := concat(" ", array.concat([raw_first], [a[1] |
	some a in assigns
	regex.match(concat("", [`\b`, a[0], `\b`]), regex.replace(raw_first, `"(?:\\.|[^"\\])*"`, `""`))
]))

_j13_param_concat(lines, i, raw_first, assigns) if {
	ps := _j13_string_params(lines, i)
	count(ps) > 0
	txt := _j13_expr_text(raw_first, assigns)
	not regex.match(_j13_sanitizer_re, txt)
	some v in _j13_quoted_concats(txt)
	v in ps
	not helpers.flow_consts(lines, i)[v]
}

_j13_vulnerable(lines, i, arg, _, _, t) if {
	not regex.match(_j13_sanitizer_re, arg)
	_j13_reach_live(lines, i, arg, t)
	not _j13_validated(lines, i, arg, t)
}

_j13_vulnerable(lines, i, _, raw_first, assigns, _) if _j13_param_concat(lines, i, raw_first, assigns)

_reported_by_java_013(content, lines, i, line) if {
	some s in _j13_sinks
	regex.match(s[0], content)
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	not regex.match(`\bPattern\s*\.\s*compile\s*\(`, line)
	regex.match(s[1], _j13_blank(line))
	raw := _j13_raw_stmt(lines, i)
	arg := _j13_first_arg(raw, s[1])
	raw_first := _j13_first_raw(raw, s[1])
	assigns := _j13_assigns(lines, i)
	t := _j13_tainted(lines, i, assigns)
	_j13_vulnerable(lines, i, arg, raw_first, assigns, t)
}

# The value was checked against a pattern or an allowlist a few lines above:
# if (!id.matches("[0-9]+")) throw ...; ALLOWED.contains(field).
_j13_validated(lines, i, arg, t) if {
	refs := {v | some v in t; regex.match(concat("", [`\b`, v, `\b`]), arg)}
	count(refs) > 0
	every v in refs {
		some j in numbers.range(max([0, i - 15]), i - 1)
		contains(lines[j], v)
		not helpers.is_comment_line(lines[j])
		regex.match(concat("", [`\b`, v, `\s*\.\s*matches\s*\(|\bmatcher\s*\(\s*`, v, `\s*\)\s*\.\s*matches\s*\(|\bPattern\s*\.\s*matches\s*\([^;]*\b`, v, `\b|\.\s*contains(?:Key)?\s*\(\s*`, v, `\s*\)`]), lines[j])
	}
}

# ── In-method flow ───────────────────────────────────────────────────────
# Read the method before reporting: the request value must still reach the
# argument once definitions on branches a constant condition or switch never
# takes are dropped, and locals that provably hold a constant (a literal, a
# constant list index or map key, a same-file method returning a constant)
# stop carrying it.
_j13_live(_, _, args) if _j13_is_src(args)

_j13_live(lines, i, args) if {
	not _j13_is_src(args)
	seeds := _j13_seeds(lines, i, _j13_assigns(lines, i)) | helpers.flow_carrier_seeds(lines, i, _j13_src_re)
	helpers.flow_reaches(lines, i, args, seeds, _j13_sanitizer_re)
}

# A value the 40-line window already links to the request, confirmed by the
# method; or one only the method-wide reading links (an assignment longer
# than the window's six lines, a value carried through a list or map).
_j13_reach_live(lines, i, args, t) if {
	_j13_reaches(args, t)
	_j13_live(lines, i, args)
}

_j13_reach_live(lines, i, args, t) if {
	not _j13_reaches(args, t)
	_j13_any_seed(lines, i, t)
	_j13_live(lines, i, args)
}

# Look-back windows end at the enclosing method's declaration (its
# annotated parameters are sources), at most 120 lines up.
_j13_wstart(lines, i) := max([0, helpers.flow_method_start(lines, i) - 1])

_j13_any_seed(_, _, t) if count(t) > 0

_j13_any_seed(lines, i, t) if {
	count(t) == 0
	count(helpers.flow_carrier_seeds(lines, i, _j13_src_re)) > 0
}
