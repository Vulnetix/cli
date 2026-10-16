package vulnetix.rules.vnx_java_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-009",
	"name": "Java path traversal",
	"description": "A file path is built from HTTP request data and opened: new File/FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile, Paths.get, Path.of, Path.resolve/resolveSibling, Files.readAllBytes/readAllLines/readString/lines/newInputStream/newOutputStream/newBufferedReader/newBufferedWriter/delete/deleteIfExists/createFile/createDirectories, or Spring's FileSystemResource/ResourceUtils.getFile, where an argument is a servlet request value (getParameter and its wrappers, getParameterValues/getParameterMap, getHeader/getHeaders, getQueryString, getPathInfo, getRequestURI, getCookies and a cookie's getValue, MultipartFile.getOriginalFilename, Part.getSubmittedFileName), a Spring or JAX-RS annotated handler parameter (@RequestParam, @PathVariable, @RequestHeader, @CookieValue, @RequestBody, @ModelAttribute, @QueryParam, @PathParam, @FormParam, @HeaderParam), or a local assigned from one up to five assignments (or a for-each over one, such as for (Cookie c : request.getCookies())) earlier within the enclosing method (at most 120 lines up). A call or assignment that continues on the next lines is read to the end of its statement. Before reporting, the enclosing method is read: definitions on a branch that a constant condition (integer literals and int locals assigned once), a constant ternary or a switch on a constant never takes are dropped; a local that provably holds a constant at the call (a literal, the element a list index or map key holds, the result of a same-file method whose every return is constant) stops carrying the request value; and a request value stored in a list, map or builder and read back is followed. A value the analysis cannot resolve stays reported. Not reported: a value checked against traversal (startsWith on the resolved or canonical path, contains(\"..\"), matches(...), an allowlist contains(...)), reduced to a bare file name (FilenameUtils.getName, getFileName()) or converted to a number (Integer.parseInt, Long.parseLong), request bodies and streams written as file content rather than used as the path, headers of an HTTP client response, the same path reported again when it is opened after the line that built it, constant paths, and sink names inside string literals or comments. Flows into another file, and into another method except a same-file method whose every return is constant, are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-009/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file-access", "lfi"],
}

# ── Request taint (local) ────────────────────────────────────────────────

# Request values that name a path. Request bodies as streams are content,
# not a path, and are left out on purpose.
_src_re := `\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getServletPath|getCookies|getOriginalFilename|getSubmittedFileName)\s*\(|\b\w*[Cc]ookie\.getValue\s*\(`

# Headers of an HTTP client's response and servlet init/type parameters are
# not request data.
_not_src_re := `(?i)\b\w*resp\w*(?:\(\))?\s*\.\s*getHeaders?\s*\(|\.get(?:Init|Type|Generic|Context)\w*Parameter\w*\s*\(`

_is_src(s) if {
	regex.match(_src_re, s)
	regex.match(_src_re, regex.replace(s, _not_src_re, ""))
}

_ann_re := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?([\w.]+)(?:<[^>]*>)?(?:\[\])?\s+(\w+)`

_gate_re := `(?m)(\.(?:get\w*Parameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getPathInfo|getRequestURI|getServletPath|getCookies|getOriginalFilename|getSubmittedFileName)\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b)`

# A transformation that removes the traversal: a bare file name, a number, a
# generated identifier.
_sanitizer_re := `FilenameUtils\.getName\s*\(|\.getFileName\s*\(\s*\)|Integer\.parseInt\s*\(|Integer\.valueOf\s*\(|Long\.parseLong\s*\(|Long\.valueOf\s*\(|UUID\.|encodeForURL|\.replaceAll\s*\(\s*"\[\^|\b[A-Z][A-Z0-9_]{2,}\s*\.\s*get(?:OrDefault)?\s*\(`


# The path object is only built to take its last component:
# Paths.get(name).getFileName(), new File(name).getName().
_bare_name_after_re := `(?:\b(?:Paths\.get|Path\.of)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*\.\s*getFileName|\bnew\s+File\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*\.\s*getName)\s*\(\s*\)`

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
# `bar =\n    new String(decode(param))` is read as one.
_assign_text(lines, j) := lines[j] if regex.match(`;\s*$`, lines[j])

_assign_text(lines, j) := concat(" ", [lines[k] | some k in numbers.range(j, e)]) if {
	not regex.match(`;\s*$`, lines[j])
	last := min([count(lines) - 1, j + 6])
	ends := [k | some k in numbers.range(j, last); regex.match(`;\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

# [name, statement text] for every assignment in the window above line i.
_assigns(lines, i) := [[v, _assign_text(lines, j)] |
	some j in numbers.range(_wstart(lines, i), i - 1)
	not helpers.is_comment_line(lines[j])
	v := _assigned(lines[j])
]

# An annotated parameter of a stream or multipart type is content; its
# getOriginalFilename() is caught as a source call instead.
_ann_names(line) := {m[2] |
	some m in regex.find_all_string_submatch_n(_ann_re, line, -1)
	not m[1] in {"MultipartFile", "InputStream", "Part", "byte", "Resource"}
}

_seeds(lines, i, assigns) := {a[0] |
	some a in assigns
	_is_src(a[1])
	not regex.match(_sanitizer_re, a[1])
} | {v |
	some j in numbers.range(_wstart(lines, i), i - 1)
	contains(lines[j], "@")
	not helpers.is_comment_line(lines[j])
	some v in _ann_names(lines[j])
} | {m[1] |
	# for (Cookie c : req.getCookies()) makes c request data.
	some j in numbers.range(_wstart(lines, i), i - 1)
	contains(lines[j], "for")
	some m in regex.find_all_string_submatch_n(_foreach_src_re, lines[j], 1)
	_is_src(m[2])
}

_foreach_src_re := `\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*:\s*([^;]*\))\s*\)`

# for (Cookie c : cookies) carries the taint of cookies to c.
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

# Names holding request data at line i: assigned from a source, an annotated
# handler parameter, or up to five assignments away from one.
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

_sink_re := `\bnew\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(|\bnew\s+(?:[\w.]+\.)?FileSystemResource\s*\(|\b(?:Paths\.get|Path\.of|ResourceUtils\.getFile)\s*\(|\.(?:resolve|resolveSibling)\s*\(|\bFiles\.(?:readAllBytes|readAllLines|readString|lines|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|delete|deleteIfExists|createFile|createDirectories|createDirectory)\s*\(`

# The argument list of the first sink call in the statement, balanced to two
# levels of nesting; the rest of the statement when it does not close.
_sink_args(stmt) := [a |
	some m in regex.find_all_string_submatch_n(concat("", ["(?:", _sink_re, ")(.*)"]), stmt, -1)
	a := _balanced(m[1])
]

_balanced(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, tail, 1)
	count(m) > 0
} else := tail

_reaches(args, _) if _is_src(args)

_reaches(args, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), args)
}

_refs(args, t) := {v | some v in t; regex.match(concat("", [`\b`, v, `\b`]), args)}

# A check on the value, or on the path built from it, before or just after
# the sink.
_guard_tail := `(?:\s*\.\s*\w+\s*\([^()]*\))*\s*\.\s*(?:startsWith\s*\(|contains\s*\(\s*"\.\."|indexOf\s*\(\s*"\.\."|matches\s*\()`

_guarded(lines, i, names) if {
	some v in names
	some j in numbers.range(_wstart(lines, i), min([count(lines) - 1, i + 8]))
	g := lines[j]
	contains(g, v)
	not helpers.is_comment_line(g)
	regex.match(concat("", [`\b`, v, `\b`, _guard_tail, `|(?:contains|containsKey|isValid\w*|validate\w*|isSafe\w*)\s*\(\s*`, v, `\s*\)`]), g)
}

# Every tainted name in the call was produced by an earlier sink statement,
# which is already reported.
_derived_from_sink(lines, i, refs) if {
	count(refs) > 0
	every v in refs {
		some j in numbers.range(_wstart(lines, i), i - 1)
		_assigned(lines[j]) == v
		regex.match(_sink_re, _blank(lines[j]))
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_hit(lines, i, line)
	not _continuation_of_hit(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "File path built from HTTP request data; resolve it against a fixed base directory, normalise it and check that the result still starts with the base, or reduce it to a bare file name, before opening it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# `Files.readAllBytes(\n    Paths.get(root, name))` is one statement and is
# reported once, on its first line.
_continuation_of_hit(lines, i) if {
	i > 0
	prev := lines[i - 1]
	not regex.match(`[;{}]\s*$`, prev)
	_hit(lines, i - 1, prev)
}

_hit(lines, i, line) if {
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _blank(line))
	stmt := _stmt(lines, i)
	t := _tainted(lines, i)
	some args in _sink_args(stmt)
	not regex.match(_sanitizer_re, args)
	_reach_live(lines, i, args, t)
	refs := _refs(args, t)
	names := refs | {v | v := _assigned(line)}
	not _guarded(lines, i, names)
	not _derived_from_sink(lines, i, refs)
	not regex.match(_bare_name_after_re, stmt)
}

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
