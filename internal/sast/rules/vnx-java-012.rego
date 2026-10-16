package vulnetix.rules.vnx_java_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-012",
	"name": "Java LDAP injection",
	"description": "An LDAP search filter or base DN is built from HTTP request data: JNDI DirContext/InitialDirContext/LdapContext.search, Spring LDAP LdapTemplate/LdapOperations search/searchForObject/searchForContext/find/findOne and LdapQueryBuilder filter(...), and UnboundID Filter.create, new SearchRequest(...) and LDAPConnection.search/searchForEntry. Reported when an argument of the call is a servlet request value (getParameter and its wrappers, getHeader, getQueryString, getCookies, the request body), a Spring or JAX-RS annotated handler parameter, or a local assigned from one up to five assignments earlier within the enclosing method (at most 120 lines up) (a filter built by concatenation or String.format a few lines above); and, for directory-lookup helpers such as authenticate(String username, ...), when a String parameter of the enclosing public/protected/private method is concatenated into a filter or DN value (\"(uid=\" + username + \")\", String.format(\"(mail=%s)\", email)), directly or through such a local. A multi-line call is reported once, on its first line; a call that continues on the next lines is read to the end of its statement. Before reporting, the enclosing method is read: definitions on a branch that a constant condition (integer literals and int locals assigned once), a constant ternary or a switch on a constant never takes are dropped; a local that provably holds a constant at the call (a literal, the element a list index or map key holds, the result of a same-file method whose every return is constant) stops carrying the request value; and a request value stored in a list, map or builder and read back is followed. A value the analysis cannot resolve stays reported. Not reported: parameterised filters ({0} placeholders with the values passed as filter arguments), values encoded with LdapEncoder.filterEncode/nameEncode, UnboundID Filter.encodeValue/createEqualityFilter, ESAPI encodeForLDAP/encodeForDN or Rdn.escapeValue, Spring filter objects (EqualsFilter, AndFilter, LikeFilter) that encode their values, constant filters, Java stream filter(...) lambdas, and sink names in comments or string literals. Flows into another file, and into another method except a same-file method whose every return is constant, are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-012/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [90],
	"capec": ["CAPEC-136"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ldap", "injection", "authentication"],
}

# ── Sinks, each enabled by a type the file names ─────────────────────────

_sinks := [
	[`DirContext|LdapContext|javax\.naming`, `\.search\s*\(`],
	[`LdapTemplate|LdapOperations`, `\.(?:search|searchForObject|searchForContext|find|findOne)\s*\(`],
	[`LdapQueryBuilder`, `\.filter\s*\(`],
	[`HardcodedFilter`, `\bnew\s+HardcodedFilter\s*\(`],
	[`com\.unboundid`, `\bFilter\.create\s*\(|\bnew\s+SearchRequest\s*\(|\.search(?:ForEntry)?\s*\(`],
]

_gate_re := `(?m)(\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies|getInputStream|getReader)\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b)`

# ── Request taint (local) ────────────────────────────────────────────────

_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getCookies|getInputStream|getReader)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

# Encoders and filter objects that escape the value they are given.
_sanitizer_re := `LdapEncoder\.\w+\s*\(|Filter\.encodeValue\s*\(|Filter\.create(?:Equality|Substring|GreaterOrEqual|LessOrEqual|Present|Approximate)\w*\s*\(|encodeForLDAP|encodeForDN|Rdn\.escapeValue|new\s+(?:Equals|Like|Present|Not|Whitespace|GreaterThanOrEquals|LessThanOrEquals)Filter\s*\(|Integer\.parseInt\s*\(|Long\.parseLong\s*\(|(?i:\bescape\w*(?:ldap|filter|dn)\w*\s*\(|\bldap\w*(?:escape|encode)\w*\s*\()`


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
	some j in numbers.range(_wstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _assigned(lines[j])
]

_ann_names(line) := {m[2] | some m in regex.find_all_string_submatch_n(_ann_re, line, -1)}

_seeds(lines, i, assigns) := {a[0] |
	some a in assigns
	_is_src(a[1])
	not regex.match(_sanitizer_re, a[1])
} | {v |
	some j in numbers.range(_wstart(lines, i), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _ann_names(lines[j])
}

_foreach_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*(\w+)\s*\)`

_foreach(lines, i) := [[m[1], m[2]] |
	some j in numbers.range(_wstart(lines, i), i - 1)
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

_raw_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 4])
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

# A placeholder filter whose values travel as filter arguments.
_parameterised(raw) if regex.match(`"[^"]*\{\d+\}[^"]*"`, raw)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_file_gate(content)
	sinks :=[x | some x in _sinks; regex.match(x[0], content)]
	count(sinks) > 0
	lines := split(content, "\n")
	some i, line in lines
	_hit(lines, i, line, sinks)
	not _continuation_of_hit(lines, i, sinks)
	finding := {
		"rule_id": metadata.id,
		"message": "LDAP filter or DN built from request data; use a parameterised filter ({0} placeholders with filter arguments), Spring LDAP filter objects or LdapQueryBuilder with parameters, or encode the value with LdapEncoder.filterEncode / Filter.encodeValue",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hit(lines, i, line, sinks) if {
	some s in sinks
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	regex.match(s[1], _blank(line))
	raw := _raw_stmt(lines, i)
	not _parameterised(raw)
	t := _tainted(lines, i)
	some args in _args(_blank(raw), s[1])
	not regex.match(`^\s*\(?\s*\w*\s*(?:,\s*\w+\s*)*\)?\s*->|^\s*[\w.]+::`, args)
	not regex.match(_sanitizer_re, args)
	_reach_live(lines, i, _strip_encoded(args), t)
}

_file_gate(content) if regex.match(_gate_re, content)

_file_gate(content) if regex.match(`=\s*"\s*\+|=%s`, content)

# Directory-lookup helpers: a String parameter of the enclosing method
# concatenated into a filter or DN value ("(uid=" + username + ")",
# String.format("(mail=%s)", email)), directly or through a local built a
# few lines above. authenticate(String username, ...) is the usual shape.
_hit(lines, i, line, sinks) if {
	some s in sinks
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	regex.match(s[1], _blank(line))
	raw := _raw_stmt(lines, i)
	not _parameterised(raw)
	ps := _string_params(lines, i)
	count(ps) > 0
	some args in _args(_blank(raw), s[1])
	not regex.match(`^\s*\(?\s*\w*\s*(?:,\s*\w+\s*)*\)?\s*->|^\s*[\w.]+::`, args)
	txt := concat(" ", array.concat([raw], [a[1] |
		some a in _assigns(lines, i)
		regex.match(concat("", [`\b`, a[0], `\b`]), args)
	]))
	some v in _filter_concats(txt)
	v in ps
	not helpers.flow_consts(lines, i)[v]
}

_filter_concats(s) := {m[1] |
	some m in regex.find_all_string_submatch_n(`=\s*"\s*\+\s*(\w+)\s*(?:\+|\))`, s, -1)
} | {id |
	some m in regex.find_all_string_submatch_n(`\b(?:String\.format|formatted)\s*\(\s*"[^"]*=%s[^"]*"\s*,\s*([^;]*)`, s, -1)
	some x in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\b`, m[1], -1)
	id := x[1]
}

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

# ldap.search(\n query().filter("(cn=" + name + ")"), mapper) is one
# statement and is reported once, on the line where it starts.
_continuation_of_hit(lines, i, sinks) if {
	i > 0
	some k in numbers.range(max([0, i - 3]), i - 1)
	every m in numbers.range(k, i - 1) {
		not regex.match(`[;{}]\s*$`, lines[m])
	}
	_hit(lines, k, lines[k], sinks)
}

# LdapQueryBuilder criteria encode their value: where("uid").is(uid).
_strip_encoded(args) := regex.replace(args, `\.\s*(?:is|like|gte|lte|whitespaceWildcardsLike)\s*\(\s*[\w.]+(?:\(\s*\))?\s*\)`, ".is()")

# ── In-method flow ───────────────────────────────────────────────────────
# Read the method before reporting: the request value must still reach the
# argument once definitions on branches a constant condition or switch never
# takes are dropped, and locals that provably hold a constant (a literal, a
# constant list index or map key, a same-file method returning a constant)
# stop carrying it.
_live(_, _, args) if _is_src(args)

_live(lines, i, args) if {
	not _is_src(args)
	seeds := _seeds(lines, i, _assigns(lines, i)) | helpers.flow_carrier_seeds(lines, i, _src_re)
	helpers.flow_reaches(lines, i, args, seeds, _sanitizer_re)
}

# A value the 40-line window already links to the request, confirmed by the
# method; or one only the method-wide reading links (an assignment longer
# than the window's six lines, a value carried through a list or map).
_reach_live(lines, i, args, t) if {
	_reaches(args, t)
	_live(lines, i, args)
}

_reach_live(lines, i, args, t) if {
	not _reaches(args, t)
	_any_seed(lines, i, t)
	_live(lines, i, args)
}

# Look-back windows end at the enclosing method's declaration (its
# annotated parameters are sources), at most 120 lines up.
_wstart(lines, i) := max([0, helpers.flow_method_start(lines, i) - 1])

_any_seed(_, _, t) if count(t) > 0

_any_seed(lines, i, t) if {
	count(t) == 0
	count(helpers.flow_carrier_seeds(lines, i, _src_re)) > 0
}
