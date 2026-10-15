package vulnetix.rules.vnx_node_014

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-014",
	"name": "NoSQL injection in MongoDB",
	"description": "A MongoDB query filter (the first argument of find, findOne, findOneAndUpdate/Delete/Replace, updateOne/updateMany/update, replaceOne, deleteOne/deleteMany, remove, count/countDocuments, distinct or aggregate) is taken from the incoming request: the whole filter is a req/request query or body value (find(req.query)), a filter member's value is one ({ username: req.body.username }, shorthand { email } after const { email } = req.body), or a $where clause concatenates or interpolates one; the request value may also come through a variable assigned (or destructured) from it in the 25 lines above, directly or through one intermediate assignment such as const filter = { owner: req.query.owner }. Express and Koa parse a[$ne]=x into an object, so a member value can carry query operators ($ne, $gt, $regex) that bypass authentication or match every document, and $where runs JavaScript on the server. Not reported: values cast to a primitive or an ObjectId (String(), Number(), parseInt(), .toString(), new ObjectId()), wrapped in { $eq: ... }, passed through mongo-sanitize/sanitize, findById, SQL ORMs whose filters sit under a where: key (Sequelize, TypeORM, Prisma), Array.prototype.find with a callback, constant filters, request values used only in the update document, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-014/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [943],
	"capec": ["CAPEC-676"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["nosql", "mongodb", "injection", "database"],
}

_msg := "MongoDB filter built from request input (NoSQL injection): a parsed object such as {\"$ne\": null} turns an equality into an operator, and $where runs JavaScript. Cast each value to the expected type (String(), new ObjectId()) or use { $eq: value }, and never build $where from input"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers)\b`

_sink := `\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|findOneAndReplace|updateOne|updateMany|update|replaceOne|deleteOne|deleteMany|remove|count|countDocuments|distinct|aggregate)\s*\(`

# A quoted string holding ${ is the inside of a template literal (`a '${x}'`)
# and is kept, so the interpolation stays visible.
_blank(s) := regex.replace(s, `'(?:[^'\\$]|\\.|\$[^{'])*'|"(?:[^"\\$]|\\.|\$[^{"])*"`, "''")

_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text after its opening parenthesis, continued over at most six
# further lines while its parentheses are open.
_call_text(lines, i, rest) := rest if _opens(rest) < 0

_call_text(lines, i, rest) := t if {
	_opens(rest) >= 0
	last := min([count(lines) - 1, i + 6])
	last >= i + 1
	t := concat(" ", array.concat([rest], array.slice(lines, i + 1, last + 1)))
}

_call_text(lines, i, rest) := rest if {
	_opens(rest) >= 0
	i + 1 > count(lines) - 1
}

# The first top-level argument; strings, template literals and bracketed
# groups (two levels deep) are taken whole.
_arg_re := "^(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|\\((?:[^()]|\\([^()]*\\))*\\)|\\[(?:[^\\[\\]]|\\[[^\\[\\]]*\\])*\\]|\\{(?:[^{}]|\\{[^{}]*\\})*\\}|[^,()\\[\\]{}'\"`])*"

_first_arg(t) := regex.find_n(_arg_re, trim_left(t, " \t"), 1)[0]

_refs(text, names) if {
	some n in names
	contains(text, n)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `(?:\s*$|\s*[^\s:\w$])`]), text)
}

_binding(item) := v if {
	lhs := trim_space(split(item, "=")[0])
	parts := split(lhs, ":")
	v := trim_left(trim_space(parts[count(parts) - 1]), ".")
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_destructured(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(.*)$`, l, 1)
	count(m) > 0
	regex.match(src, m[0][2])
	some item in split(m[0][1], ",")
	v := _binding(item)
}

# One further hop through an assignment that uses a tainted name, unless that
# assignment picks the value from a fixed list ([...].includes(x) ? x : y).
_tainted(lines, i, src) := t if {
	t1 := (_direct(lines, i, src) | _destructured(lines, i, src)) | _prop_assigned(lines, i, src)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(_neutralised(l), t1)
		v := helpers.assigned_first(l)
		not regex.match(`\]\s*\.includes\s*\(`, l)
	}
	t := t1 | t2
}

# Names assigned from a request value. A lookup keyed by one (a session
# fetched with req.cookies.token, a record found by req.params.id) returns
# server data, not the client's string.
_direct(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(src, _neutralised(l))
	not regex.match(_lookup_re, l)
	v := helpers.assigned_first(l)
}

# A filter built member by member (if (req.query.status) filter.status =
# req.query.status): the object named on the left is tainted.
_prop_assigned(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(src, l)
	m := regex.find_all_string_submatch_n(`(?:^|[\s;{)])([A-Za-z_$][\w$]*)(?:\.[\w$]+|\[[^\]]+\])+\s*=\s*([^=].*)$`, l, 1)
	count(m) > 0
	regex.match(src, _neutralised(m[0][2]))
	v := m[0][1]
	not v in {"req", "request", "ctx", "res", "response", "this", "module", "exports"}
}

_lookup_re := `=\s*(?:await\s+)?[\w.$?]+\.(?:get|findOne|findByPk|findById|findUnique|verify|decode|has)\(\s*(?:req|request|ctx)\b`

_reaches(a, _, _, src) if regex.match(src, a)

_reaches(a, lines, i, src) if _refs(a, _tainted(lines, i, src))

# Values a body or query parser can turn into an object. Route params and
# headers are always strings, so they can only inject through $where.
_src_obj := `\b(?:req|request)\.(?:query|body|cookies|payload)\b|\bctx\.(?:request\.)?(?:query|body)\b`

_injectable(a, lines, i) if _reaches(_neutralised(a), lines, i, _src_obj)

_injectable(a, lines, i) if {
	contains(a, "$where")
	_reaches(a, lines, i, _src)
}

# Casts and sanitisers that leave no operator object: removed before the
# filter is examined.
_neutralised(a) := regex.replace(
	regex.replace(
		regex.replace(a, `(?:\bnew\s+)?(?:\b[\w$.]*ObjectId|\bString|\bNumber|\bparseInt|\bparseFloat|\bBoolean|\bmongoSanitize|\bsanitize\w*|\bescape\w*)\s*\((?:[^()]|\([^()]*\))*\)`, "_"),
		`\$eq\s*:\s*[^,}]+`, "_",
	),
	`[\w$.\[\]'"]+\.toString\(\s*\)`, "_",
)

# A filter is the whole first argument, or a $where clause. SQL ORMs nest
# their filter under where: (not $where), and a callback is Array.find.
_filter_ok(a) if not regex.match(`(?:^|[^\w$])where\s*:|=>|\bfunction\b`, a)

# The request value was checked to be a primitive (typeof x !== 'string') in
# the lines above.
_type_checked(lines, i) if regex.match(`\btypeof\s+[^=!;]+[!=]==?\s*['"](?:string|number|boolean)['"]`, helpers.code_window(lines, i, 25, 0))

# MongoDB's update/replace calls take (filter, update). One argument is an
# ORM instance update (user.update({ username })), and a second argument
# holding where: is Sequelize's Model.update(values, { where }).
_update_call(sink_text) if regex.match(`\.(?:findOneAndUpdate|findOneAndReplace|updateOne|updateMany|update|replaceOne)\s*\($`, sink_text)

_shape_ok(sink_text, _, _) if not _update_call(sink_text)

_shape_ok(sink_text, t, a) if {
	_update_call(sink_text)
	after := trim_left(substring(trim_left(t, " \t"), count(a), -1), " \t")
	startswith(after, ",")
	second := trim_space(trim_left(after, ","))
	second != ""
	not startswith(second, ")")
	not regex.match(`^\{\s*where\s*:`, second)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(`\.(?:find|update|delete|remove|replace|count|distinct|aggregate)`, content)
	not regex.match(`express-mongo-sanitize|\bsanitizeFilter\s*:\s*true|\bsanitizeFilter\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _blank(line)
	regex.match(_sink, code)
	parts := regex.split(_sink, code)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	a := _first_arg(t)
	trim_space(a) != ""
	_filter_ok(a)
	_shape_ok(regex.find_n(_sink, code, 1)[0], t, a)
	_injectable(a, lines, i)
	not _type_checked(lines, i)
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
