package vulnetix.rules.vnx_java_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-015",
	"name": "Java JPQL/HQL injection via string concatenation",
	"description": "A JPQL, HQL or native SQL string passed to JPA EntityManager.createQuery/createNativeQuery or Hibernate Session.createQuery/createNativeQuery/createSelectionQuery/createMutationQuery/createNativeMutationQuery/createFilter is built from untrusted text. Reported when the query argument (the first argument) is, or names a local built from, a servlet request value (getParameter and its wrappers, getHeader, getQueryString, getCookies), a Spring or JAX-RS annotated handler parameter, or a local assigned from one up to five assignments earlier within 40 lines (concatenation, String.format, StringBuilder); and, for repository code, when the query concatenates a String parameter of the enclosing public/protected/private method into a quoted or compared value ('\" + email, = \" + id, ORDER BY \" + sort) or passes it to String.format with %s, directly or through a local built a few lines above. A call that continues on the next lines is read to the end of its statement. Not reported: named (:name) and positional (?1) parameters bound with setParameter, createNamedQuery, CriteriaQuery objects, constant queries and UPPER_CASE constants, entity or table names concatenated outside a value position (generic DAOs using getSimpleName()), values converted to numbers, Session.createSQLQuery (VNX-JAVA-003 reports it with JDBC), and the pattern in comments or string literals. Flows into another method or file are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-015/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["sql-injection", "jpql", "jpa", "java"],
}

_msg := "JPQL/HQL query built from untrusted input; use named parameters (:param) or positional parameters (?1) bound with setParameter(), or the Criteria API, instead of concatenating values into the query"

_file_re := `EntityManager|org\.hibernate|javax\.persistence|jakarta\.persistence|\bSession\b`

_sink_re := `\.(?:createQuery|createNativeQuery|createSelectionQuery|createMutationQuery|createNativeMutationQuery|createFilter)\s*\(`

# ── Request taint (local) ────────────────────────────────────────────────

_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

_sanitizer_re := `Integer\.parseInt\s*\(|Integer\.valueOf\s*\(|Long\.parseLong\s*\(|Long\.valueOf\s*\(|Double\.parseDouble\s*\(|UUID\.fromString\s*\(`

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

# Assignments in the window above line i, plus StringBuilder appends
# (`sb.append(x)` makes sb carry x).
_assigns(lines, i) := array.concat(
	[[v, _assign_text(lines, j)] |
		some j in numbers.range(max([0, i - _window]), i - 1)
		not helpers.is_comment_line(lines[j])
		v := _assigned(lines[j])
	],
	[[m[1], lines[j]] |
		some j in numbers.range(max([0, i - _window]), i - 1)
		contains(lines[j], ".append(")
		not helpers.is_comment_line(lines[j])
		some m in regex.find_all_string_submatch_n(`^\s*(\w+)\s*\.\s*append\s*\(`, lines[j], 1)
	],
)

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
	ends := [k | some k in numbers.range(i, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# The query argument, with string literals blanked (for the taint check) and
# intact (for the value-position check).
_first_arg(raw) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", ["(?:", _sink_re, ")((?:[^(),]|\\((?:[^()]|\\([^()]*\\))*\\))*)"]), _blank(raw), 1)
	count(m) > 0
}

_first_raw(raw) := _raw_first(m[0][1]) if {
	m := regex.find_all_string_submatch_n(concat("", ["(?:", _sink_re, ")(.*)"]), raw, 1)
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

_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized|default)\s+)+[\w.<>\[\], ?]+\s+\w+\s*\(([^)]*)`

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

# Idents placed where a value goes: '" + x, = " + x, LIKE " + x, IN (" + x,
# ORDER BY ...." + x, and String.format arguments of a %s query.
_value_concats(s) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?i)(?:'|[=<>]\s*|\blike\s+|\bin\s*\(\s*|\border\s+by\s+[\w.]*)"\s*\+\s*(\w+)`, s, -1)
} | {id |
	some m in regex.find_all_string_submatch_n(`\b(?:String\.format|formatted)\s*\(\s*"[^"]*%s[^"]*"\s*,\s*([^;]*)`, s, -1)
	some x in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\b`, m[1], -1)
	id := x[1]
}

_expr_text(raw_first, assigns) := concat(" ", array.concat([raw_first], [a[1] |
	some a in assigns
	regex.match(concat("", [`\b`, a[0], `\b`]), _blank(raw_first))
]))

_param_concat(lines, i, raw_first, assigns) if {
	ps := _string_params(lines, i)
	count(ps) > 0
	txt := _expr_text(raw_first, assigns)
	some v in _value_concats(txt)
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
	contains(content, "create")
	regex.match(_file_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "create")
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _blank(line))
	raw := _raw_stmt(lines, i)
	arg := _first_arg(raw)
	regex.match(`[A-Za-z_]`, arg)
	raw_first := _first_raw(raw)
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
