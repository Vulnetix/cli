# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1284

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1284",
	"name": "Improper Validation of Specified Quantity in Input",
	"description": "A quantity the client chose (a request field named quantity, qty, amount, units, credits, points, coins, num_items, deposit or withdraw/withdrawal) is used in a balance, stock or price calculation, or stored on an order, cart or wallet record, with no check that it is positive and within limits, so a negative or huge value moves money the wrong way, creates stock or overflows a total. Reported in Python (Flask/Django/DRF request.args/form/values/json/GET/POST/data/query_params) and JavaScript/TypeScript (req.body/query/params, including const { quantity } = req.body): the value, inline or through a variable assigned from it in the 20 lines above (including a TypeScript-annotated const), used in x += / -= / *= arithmetic, a $inc update, a multiplication, an x = y + / - arithmetic assignment, or as a quantity-named field (or shorthand property) of an ORM create/update/insert/save/build/upsert, $inc or $set. Not reported: a comparison of the value (<, <=, >, >=, in range(...)) or a max()/abs()/clamp/positive check between the read and the use, a file that validates with a schema (Joi/yup/zod .positive() or .min(0|1), pydantic conint/confloat/PositiveInt/gt=0/ge=1, express-validator isInt/isFloat({ min | gt })), the local assignment that reads the value, a value that is only displayed, counts and page sizes (judged by VNX-400 and VNX-606), and text in comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1284/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1284],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-validation-of-specified-quantity", "business-logic", "cwe-1284"],
}

_msg := "A client-supplied quantity or amount is used in a balance, price or stock calculation (or stored on a record) without checking that it is positive and within limits. Reject values below 1 (or 0) and above a maximum before using it"

_key := `(?i:quantity|qty|amount|units|credits|points|coins|num_?items|deposit|withdraw)`

_src := {
	"py": concat("", [`\brequest\s*\.\s*(?:args|form|values|json|GET|POST|data|query_params)\s*(?:\.\s*get\s*\(\s*|\[\s*)['"]\w*`, _key, `\w*['"]`]),
	"js": concat("", [`\breq(?:uest)?\s*\.\s*(?:body|query|params)\s*(?:\.\s*\w*`, _key, `\w*\b|\[\s*['"]\w*`, _key, `\w*['"]\s*\])`]),
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_gate := {
	"py": concat("", [`request\s*\.[\s\S]*`, _key]),
	"js": concat("", [`req(?:uest)?\s*\.\s*(?:body|query|params)[\s\S]*`, _key]),
}

# A schema or validator elsewhere in the file bounds the input.
_file_validated(content) if regex.match(`\.positive\s*\(|\.min\s*\(\s*[01]\s*\)|\bconint\s*\(|\b(?:gt|ge)\s*=\s*[01]\b|PositiveInteger|PositiveSmallInteger|MinValueValidator|\bPositive(?:Int|Float)\b|\bNonNegative(?:Int|Float)\b|\bcon(?:float|decimal)\s*\(|\bis(?:Int|Float|Decimal|Numeric)\s*\(\s*\{[^}]*\b(?:min|gt)\s*:|\bisPositive\b`, content)

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), "`(\\\\.|[^`\\\\])*`", "``")

_conv := `(?:(?:int|float|Decimal|Number|parseInt|parseFloat)\s*\(\s*)?`

_orm := `(?i)(?:\.create\s*\(|\.update\w*\s*\(|\.insert\w*\s*\(|\.save\s*\(|\.build\s*\(|\.upsert\s*\(|bulk_create|findOneAndUpdate|findByIdAndUpdate|\$inc|\$set|\.objects\.(?:create|update|bulk|get_or_create|update_or_create))`

# Sink templates around the value expression x.
_arith_res(x) := [
	concat("", [`[\w\].)]\s*[+\-*]=\s*[^;]*?`, _conv, x]),
	concat("", [x, `\s*\)?\s*\*[^*=]`]),
	concat("", [`[^*]\*\s*`, _conv, x]),
	concat("", [`[^=!<>]=\s*[\w.\[\]]+\s*[-+]\s*`, _conv, x]),
]

_sink(lines, i, c, x, _) if {
	some re in _arith_res(x)
	regex.match(re, c)
}

_sink(lines, i, c, x, _) if {
	regex.match(concat("", [`\b\w*`, _key, `\w*['"]?\s*[:=]\s*`, _conv, x]), c)
	not _local_assignment(c)
	_orm_near(lines, i)
}

# $inc: { balance: -amount }: the value moves a stored counter.
_sink(lines, i, c, x, _) if {
	regex.match(concat("", [`\$inc\s*:\s*\{[^}]*:\s*-?\s*`, _conv, x]), c)
}

# `units = int(request.POST.get("units"))` is the read, not a record field: a
# spaced Python assignment or a JS declaration names a local.
_local_assignment(c) if regex.match(`^\s*[A-Za-z_]\w*\s+=\s`, c)

_local_assignment(c) if regex.match(`^\s*(?:const|let|var)\s`, c)

_sink(lines, i, c, _, v) if {
	v != ""
	regex.match(concat("", [`[{,]\s*`, v, `\s*[,}]`]), c)
	_orm_near(lines, i)
}

_orm_near(lines, i) if {
	some j in numbers.range(max([0, i - 2]), i)
	regex.match(_orm, lines[j])
}

_cmp(v, l) if regex.match(concat("", [`\b`, v, `\b\s*(?:<|>[^>=]|>=|<=)`]), l)

_cmp(v, l) if regex.match(concat("", [`(?:[^=<>\-]|^)(?:<|>|<=|>=)\s*`, v, `\b`]), l)

_cmp(v, l) if regex.match(concat("", [`\b`, v, `\s+(?:not\s+)?in\s+range\s*\(`]), l)

_cmp(v, l) if regex.match(concat("", [`(?i)\b(?:max|abs|clamp\w*|positive\w*|validate\w*)\s*\([^)]*\b`, v, `\b`]), l)

_guarded(lines, j, i, v) if {
	some k in numbers.range(j, i)
	not helpers.is_comment_line(lines[k])
	_cmp(v, _code(lines[k]))
}

# The source line itself bounds the value: max(1, int(...)), Math.abs(...).
_bounded_source(l) if regex.match(`(?i)\b(?:max|abs|clamp\w*)\s*\(`, l)

_is_source(lang, l) if regex.match(_src[lang], l)

_is_source("js", l) if count(_destructured(l)) > 0

# const { productId, quantity: q = 1 } = req.body
_destructured(line) := {v |
	m := regex.find_all_string_submatch_n(`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\s*\.\s*(?:body|query|params)\b`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := trim_space(split(part, "=")[0])
	regex.match(concat("", [`^\w*`, _key, `\w*`]), p)
	segs := split(p, ":")
	v := trim_space(segs[count(segs) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

# Variable form: a name assigned from a quantity field, then used.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	not _file_validated(content)
	lines := split(content, "\n")
	srcs := [j |
		some j, l in lines
		regex.match(_key, l)
		not helpers.is_comment_line(l)
		_is_source(lang, l)
		not _bounded_source(l)
	]
	count(srcs) > 0
	some j in srcs
	some v in _src_names(lines, j)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 20]))
	not helpers.is_comment_line(lines[i])
	c := _code(lines[i])
	regex.match(concat("", [`\b`, v, `\b`]), c)
	_sink(lines, i, c, concat("", [`\b`, v, `\b`]), v)
	not _reassigned(lines, j, i, v)
	not _guarded(lines, j, i, v)
	finding := _finding(path, i, lines[i])
}

_src_names(lines, j) := ns if {
	d := _destructured(lines[j])
	count(d) > 0
	ns := d
} else := ns if {
	# TypeScript: const qty: number = Number(req.body.qty)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[\w$<>\[\]|. ]+=[^=]`, lines[j], 1)
	count(m) > 0
	ns := {m[0][1]}
} else := {v |
	v := helpers.assigned_first(lines[j])
	not regex.match(`^\s*(?:if|elif|while|for|return)\b`, lines[j])
}

# The name was assigned something else between the read and the use.
_reassigned(lines, j, i, v) if {
	i - 1 >= j + 1
	some k in numbers.range(j + 1, i - 1)
	helpers.assigned_first(lines[k]) == v
	not regex.match(concat("", [`\b`, v, `\s*[+\-*]=`]), lines[k])
}

# Inline form: the request field itself is the operand.
findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	not _file_validated(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_key, line)
	not helpers.is_comment_line(line)
	regex.match(_src[lang], line)
	_sink(lines, i, line, concat("", ["(?:", _src[lang], ")"]), "")
	not _inline_guarded(lines, i, lang)
	finding := _finding(path, i, line)
}

_inline_guarded(lines, i, lang) if {
	some k in numbers.range(max([0, i - 10]), i)
	regex.match(_src[lang], lines[k])
	regex.match(`(?:[^=<>\-]|^)(?:<|>|<=|>=)[^>=]`, lines[k])
	not regex.match(`=>`, lines[k])
}

_inline_guarded(lines, i, _) if _bounded_source(lines[i])

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
