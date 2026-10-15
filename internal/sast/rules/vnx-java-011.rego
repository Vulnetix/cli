package vulnetix.rules.vnx_java_011

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-011",
	"name": "Java expression language injection",
	"description": "HTTP request data is evaluated as an expression: Spring SpEL (ExpressionParser.parseExpression/parseRaw), OGNL (Ognl.getValue/setValue/parseExpression, OgnlUtil.getValue/setValue/compile/callMethod, Struts ValueStack.findValue/findString), Jakarta/Java EE EL (ExpressionFactory.createValueExpression/createMethodExpression, ELProcessor.eval/getValue/setValue), javax.script ScriptEngine.eval, MVEL.eval/compileExpression/executeExpression and JEXL createExpression/createScript, or a Bean Validation message template (ConstraintValidatorContext.buildConstraintViolationWithTemplate) built from the value being validated. Reported when the expression argument of the call (the first; the second too for createValueExpression/createMethodExpression, whose first is the ELContext) is a servlet request value (getParameter and its wrappers, getHeader, getQueryString, getCookies, the request body), a Spring or JAX-RS annotated handler parameter, the validated value of isValid, or a local assigned from one up to five assignments earlier within 40 lines; a call that continues on the next lines is read to the end of its statement. Not reported: constant or bundled expressions, request data passed as a variable binding (engine.put, eval(script, bindings), SpEL root objects, the context or root argument of Ognl.getValue(\"fixed.path\", ctx, root)) rather than as the expression, SpEL evaluated with a SimpleEvaluationContext nearby, Hibernate message parameters (addMessageParameter), creating a parser or engine without evaluating request data, and sink names in comments or string literals. Flows into another method or file are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-011/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [917],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["el-injection", "spel", "ognl", "rce"],
}

# ── Sinks, each enabled by a type the file names ─────────────────────────

# [type the file must name, call, how many leading arguments hold the
# expression]. Only those are checked: Ognl.getValue("user.name", ctx, root)
# with request data as the root evaluates a fixed expression.
_sinks := [
	["ExpressionParser", `\.parse(?:Expression|Raw)\s*\(`, 1],
	["Ognl", `\bOgnl\.(?:getValue|setValue|parseExpression)\s*\(|\b\w*[Oo]gnlUtil\w*\.(?:getValue|setValue|compile|callMethod)\s*\(`, 1],
	["ValueStack", `\.find(?:Value|String)\s*\(`, 1],
	["ExpressionFactory", `\.create(?:Value|Method)Expression\s*\(`, 2],
	["ELProcessor", `\.(?:eval|getValue|setValue)\s*\(`, 1],
	["ScriptEngine", `\.eval\s*\(`, 1],
	["MVEL", `\bMVEL\.(?:eval|evalToString|compileExpression|executeExpression)\s*\(`, 1],
	["Jexl", `\.create(?:Expression|Script)\s*\(`, 1],
	["buildConstraintViolationWithTemplate", `\.buildConstraintViolationWithTemplate\s*\(`, 1],
]

_arg_re := `(?:[^(),]|\((?:[^()]|\([^()]*\))*\))*`

# The first n top-level arguments of an argument list.
_lead(args, 1) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", ["^(", _arg_re, ")"]), args, 1)
	count(m) > 0
} else := args

_lead(args, 2) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", ["^(", _arg_re, "(?:,", _arg_re, ")?)"]), args, 1)
	count(m) > 0
} else := args

_gate_re := `(?m)(\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies|getInputStream|getReader)\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b|ConstraintValidatorContext)`

# ── Request taint (local) ────────────────────────────────────────────────

_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies|getInputStream|getReader)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

# The value a ConstraintValidator is asked to judge is whatever the client sent.
_validated_re := `\bisValid\s*\(\s*(?:final\s+)?[\w.<>\[\]?, ]+?\s+(\w+)\s*,\s*(?:final\s+)?(?:[\w.]+\.)?ConstraintValidatorContext\b`

_sanitizer_re := `Integer\.parseInt\s*\(|Long\.parseLong\s*\(|Double\.parseDouble\s*\(`

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

_seeds(lines, i, assigns) := ({a[0] |
	some a in assigns
	_is_src(a[1])
	not regex.match(_sanitizer_re, a[1])
} | {v |
	some j in numbers.range(max([0, i - _window]), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _ann_names(lines[j])
}) | {m[1] |
	some j in numbers.range(max([0, i - _window]), i - 1)
	contains(lines[j], "isValid")
	some m in regex.find_all_string_submatch_n(_validated_re, lines[j], 1)
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

_tainted(lines, i) := t if {
	assigns := _assigns(lines, i)
	fe := _foreach(lines, i)
	t1 := _hop(assigns, fe, _hop(assigns, fe, _seeds(lines, i, assigns)))
	t := _hop(assigns, fe, _hop(assigns, fe, _hop(assigns, fe, t1)))
}

# ── Statement and argument text ──────────────────────────────────────────

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_stmt(lines, i) := concat(" ", [_blank(lines[k]) | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 3])
	ends := [k | some k in numbers.range(i, last); regex.match(`[;{]\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_balanced(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, tail, 1)
	count(m) > 0
} else := tail

_args(stmt, sink) := [_balanced(m[1]) | some m in regex.find_all_string_submatch_n(concat("", ["(?:", sink, ")(.*)"]), stmt, -1)]

_reaches(args, _) if _is_src(args)

_reaches(args, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), args)
}

_simple_context(lines, i) if {
	some j in numbers.range(max([0, i - 10]), min([count(lines) - 1, i + 3]))
	contains(lines[j], "SimpleEvaluationContext")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	some s in _sinks
	contains(content, s[0])
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	regex.match(s[1], _blank(line))
	stmt := _stmt(lines, i)
	t := _tainted(lines, i)
	some all_args in _args(stmt, s[1])
	args := _lead(all_args, s[2])
	_reaches(args, t)
	not _simple_context(lines, i)
	not _echo(lines, i, args, t)
	finding := {
		"rule_id": metadata.id,
		"message": "Request data evaluated as an expression (SpEL, OGNL, EL, script or validation template); never evaluate client input as code. Bind it as a variable or root object of a fixed expression, or use SimpleEvaluationContext for SpEL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_any_sink_re := concat("|", [s[1] | some s in _sinks])

_refs(args, t) := {v | some v in t; regex.match(concat("", [`\b`, v, `\b`]), args)}

# A compiled expression evaluated later (compileExpression then
# executeExpression) is the flow already reported where it was compiled.
_derived_from_sink(lines, i, refs) if {
	count(refs) > 0
	every v in refs {
		some j in numbers.range(max([0, i - _window]), i - 1)
		_assigned(lines[j]) == v
		regex.match(_any_sink_re, _blank(lines[j]))
	}
}

_echo(lines, i, args, t) if {
	not _is_src(args)
	_derived_from_sink(lines, i, _refs(args, t))
}
