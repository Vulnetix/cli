package vulnetix.rules.vnx_java_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-012",
	"name": "Java LDAP injection",
	"description": "An LDAP search filter or base DN is built from HTTP request data: JNDI DirContext/InitialDirContext/LdapContext.search, Spring LDAP LdapTemplate/LdapOperations search/searchForObject/searchForContext/find/findOne and LdapQueryBuilder filter(...), and UnboundID Filter.create, new SearchRequest(...) and LDAPConnection.search/searchForEntry. Reported when an argument of the call is a servlet request value (getParameter and its wrappers, getHeader, getQueryString, getCookies, the request body), a Spring or JAX-RS annotated handler parameter, or a local assigned from one up to five assignments earlier within 40 lines (a filter built by concatenation or String.format a few lines above); a call that continues on the next lines is read to the end of its statement. Not reported: parameterised filters ({0} placeholders with the values passed as filter arguments), values encoded with LdapEncoder.filterEncode/nameEncode, UnboundID Filter.encodeValue/createEqualityFilter, ESAPI encodeForLDAP/encodeForDN or Rdn.escapeValue, Spring filter objects (EqualsFilter, AndFilter, LikeFilter) that encode their values, constant filters, Java stream filter(...) lambdas, and sink names in comments or string literals. Flows into another method or file are not followed.",
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
_sanitizer_re := `LdapEncoder\.\w+\s*\(|Filter\.encodeValue\s*\(|Filter\.create(?:Equality|Substring|GreaterOrEqual|LessOrEqual|Present|Approximate)\w*\s*\(|encodeForLDAP|encodeForDN|Rdn\.escapeValue|new\s+(?:Equals|Like|Present|Not|Whitespace|GreaterThanOrEquals|LessThanOrEquals|Hardcoded)Filter\s*\(|Integer\.parseInt\s*\(|Long\.parseLong\s*\(`

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
	some s in _sinks
	regex.match(s[0], content)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(s[1], line)
	not helpers.is_comment_line(line)
	regex.match(s[1], _blank(line))
	raw := _raw_stmt(lines, i)
	not _parameterised(raw)
	t := _tainted(lines, i)
	some args in _args(_blank(raw), s[1])
	not regex.match(`^\s*\(?\s*\w*\s*(?:,\s*\w+\s*)*\)?\s*->|^\s*[\w.]+::`, args)
	not regex.match(_sanitizer_re, args)
	_reaches(args, t)
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
