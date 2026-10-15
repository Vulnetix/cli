# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_943

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-943",
	"name": "NoSQL injection in a MongoDB query (Python, PHP, Java)",
	"description": "A MongoDB query is built from untrusted data. Python (pymongo, motor): a $where clause built with an f-string, concatenation or % / .format(); or the filter (first argument) of find, find_one, find_one_and_update/delete/replace, update_one/many, delete_one/many, replace_one, count_documents or aggregate is, or has a value taken from, a parsed JSON request body (request.json, request.get_json(), request.data, json.loads(request...)) directly or through a variable assigned from it a few lines above. PHP (mongodb extension or library, in a file that mentions Mongo): a query array passed to ->find/->findOne/->updateOne/... or new MongoDB\\Driver\\Query with a $_GET/$_POST/$_REQUEST/$_COOKIE value (PHP parses name[$ne]=x into an array, which becomes an operator), or a '$where' built by concatenation or interpolation. Java: a $where or Filters.where() built by string concatenation, or Document.parse/BasicDBObject.parse/BsonDocument.parse/new BasicQuery given a JSON query string built by concatenation, String.format or a variable assigned from one. Not reported: values cast to a string or number (str(), int(), ObjectId(), (string), strval(), intval()), {\"$eq\": ...} wrappers, Flask request.args values used as plain equality values (always strings), constant $where clauses and JSON strings, typed filter builders (Filters.eq, Criteria), Doctrine/Eloquent find(), comments and string literals. Node.js MongoDB filters are reported by VNX-NODE-014.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-943/",
	"languages": ["python", "php", "java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [943],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["nosql-injection", "mongodb", "injection", "cwe-943"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Text of the call opened on line i, from the text after the method name
# through the line that balances its parentheses (at most 6 lines on).
_call_text(lines, i, rest) := txt if {
	last := min([count(lines) - 1, i + 6])
	ends := [k |
		some k in numbers.range(i, last)
		_balance(lines, i, k, rest) <= 0
	]
	end := _first_or(ends, last)
	more := [lines[k] | some k in numbers.range(i + 1, end); end > i]
	txt := concat("\n", array.concat([rest], more))
}

_first_or(arr, d) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_balance(lines, i, k, rest) := b if {
	parts := array.concat([rest], [lines[m] | some m in numbers.range(i + 1, k); k > i])
	s := concat("\n", parts)
	b := strings.count(s, "(") - strings.count(s, ")")
}

# First argument of a call whose text starts at its opening parenthesis: a
# brace/bracket literal (two nesting levels) or an expression up to the first
# top-level comma.
_first_arg(call) := a if {
	m := regex.find_all_string_submatch_n(`^\(\s*(\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}|\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]|array\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|[^,()]*(?:\([^()]*\)[^,()]*)*)`, call, 1)
	count(m) > 0
	a := m[0][1]
}

_strip_strings(s) := regex.replace(s, `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, `""`)

# ── Python ───────────────────────────────────────────────────────────────

_py_source := `\brequest\.(?:json\b|get_json\s*\(|data\b)|json\.loads\(\s*(?:await\s+)?request\b|await\s+request\.json\(`

_py_method := `\.(find|find_one|find_one_and_update|find_one_and_delete|find_one_and_replace|update_one|update_many|delete_one|delete_many|replace_one|count_documents|aggregate)\s*(\(.*)$`

_py_cast(s) := regex.replace(s, `\b(?:str|int|float|bool|ObjectId)\s*\((?:[^()]|\([^()]*\))*\)|\{\s*["']\$eq["']\s*:\s*[^{}]*\}`, "0")

# `$where` built from a non-constant string.
findings contains _finding(path, i, line, "MongoDB $where clause built from a formatted string: $where runs JavaScript on the server, so any interpolated value can rewrite the query. Use ordinary query operators with the value as data") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "$where")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$where")
	not helpers.is_comment_line(line)
	regex.match(`["']\$where["']\s*:\s*(?:[fF]["']|(?:"[^"]*"|'[^']*')\s*(?:\+|%|\.format\()|[A-Za-z_]\w*\s*\+)`, line)
}

findings contains _finding(path, i, line, "MongoDB filter taken from the parsed JSON request body (NoSQL injection): a value such as {\"$ne\": null} becomes a query operator. Cast each value to the expected type (str(), ObjectId()) or wrap it in {\"$eq\": value}") if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`request\.(?:json|get_json|data)|json\.loads\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_py_method, line, 1)
	count(m) > 0
	regex.match(_py_method, _strip_strings(line))
	arg := _first_arg(_call_text(lines, i, m[0][2]))
	clean := _strip_strings(_py_cast(arg))
	_py_tainted_arg(lines, i, clean)
}

_py_tainted_arg(_, _, clean) if regex.match(_py_source, clean)

_py_tainted_arg(lines, i, clean) if {
	some v in _py_names(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), clean)
}

# Names assigned from the request body above line i, and names assigned from
# those (data = request.get_json(); token = data.get("token")).
_py_names(lines, i) := names if {
	t1 := {v |
		some v in helpers.tainted_names(lines, i, 20, _py_source)
		not _py_cast_assign(lines, i, v)
	}
	t2 := {w |
		count(t1) > 0
		alt := concat("|", t1)
		some w in helpers.tainted_names(lines, i, 20, concat("", [`\b(?:`, alt, `)\b`]))
	}
	casted := {w | some w in t2; _py_cast_assign(lines, i, w)}
	names := (t1 | t2) - casted
}

_py_cast_assign(lines, i, v) if {
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(concat("", [`^\s*`, v, `\s*=\s*(?:str|int|float|ObjectId)\(`]), lines[j])
}

# ── PHP ──────────────────────────────────────────────────────────────────

_php_source := `\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|get|all|json)\(|json_decode\(\s*file_get_contents\(\s*['"]php://input`

_php_method := `(?:->(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|replaceOne|count|countDocuments|aggregate)|new\s+\\?(?:MongoDB\\Driver\\)?Query)\s*(\(.*)$`

_php_cast(s) := regex.replace(s, `\(\s*(?:string|int|integer|float|bool)\s*\)\s*\$\w+(?:\[[^\]]*\])*|\b(?:strval|intval|floatval|htmlspecialchars)\s*\((?:[^()]|\([^()]*\))*\)|new\s+\\?(?:MongoDB\\BSON\\)?ObjectId\((?:[^()]|\([^()]*\))*\)`, "0")

findings contains _finding(path, i, line, "MongoDB $where clause built by string concatenation or interpolation: $where runs JavaScript on the server. Use ordinary query operators with the value as data") if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "$where")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$where")
	not helpers.is_comment_line(line)
	regex.match(`'\$where'\s*=>\s*(?:(?:'[^']*'|"[^"]*")\s*\.|\$\w+\s*\.|"[^"]*\$\w)`, line)
}

findings contains _finding(path, i, line, "MongoDB query array takes a request value (NoSQL injection): PHP parses name[$ne]=x into an array, which becomes a query operator. Cast the value ((string), intval()) before querying") if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`(?i)mongo`, content)
	regex.match(`\$_(?:GET|POST|REQUEST|COOKIE)|\$request->|php://input`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_php_method, line, 1)
	count(m) > 0
	regex.match(_php_method, _strip_strings(line))
	arg := _first_arg(_call_text(lines, i, m[0][1]))
	regex.match(`^\s*(?:\[|array\()`, arg)
	clean := _php_cast(_strip_strings(arg))
	_php_tainted_arg(lines, i, clean)
}

_php_tainted_arg(_, _, clean) if regex.match(_php_source, clean)

_php_tainted_arg(lines, i, clean) if {
	i > 0
	some j in numbers.range(max([0, i - 20]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=\s*([^=].*)$`, prev, 1)
	count(m) > 0
	regex.match(_php_source, m[0][2])
	not regex.match(`^\s*(?:\(\s*(?:string|int|integer|float|bool)\s*\)|(?:strval|intval|floatval|htmlspecialchars)\s*\()`, m[0][2])
	regex.match(concat("", [`\$`, m[0][1], `\b`]), clean)
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_concat := `"\s*\+\s*[A-Za-z_(]|[A-Za-z_)\]]\s*\+\s*"`

findings contains _finding(path, i, line, "MongoDB $where clause built by string concatenation: $where runs JavaScript on the server. Use typed filters (Filters.eq, Criteria.where(...).is(...)) with the value as data") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\$where|Filters\.where\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`"\$where"|\bFilters\.where\(|^\s*where\(`, line)
	not helpers.is_comment_line(line)
	regex.match(_java_concat, _java_after_where(line))
}

_java_after_where(line) := s if {
	idx := indexof(line, "$where")
	idx >= 0
	s := substring(line, idx, -1)
}

_java_after_where(line) := s if {
	indexof(line, "$where") < 0
	s := line
}

_java_parse := `\b(?:Document|BasicDBObject|BsonDocument|JSON)\.parse\s*(\(.*)$|\bnew\s+BasicQuery\s*(\(.*)$`

findings contains _finding(path, i, line, "MongoDB query parsed from a JSON string built from a variable (NoSQL injection): a quote in the value rewrites the query. Use typed filters (Filters.eq, Criteria.where(...).is(...)) instead of string-built JSON") if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\.parse\(|new\s+BasicQuery\(`, content)
	regex.match(`(?i)mongo|org\.bson`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_java_parse, line, 1)
	count(m) > 0
	rest := concat("", [m[0][1], m[0][2]])
	arg := _first_arg(_call_text(lines, i, rest))
	_java_built(lines, i, arg)
}

_java_built(_, _, arg) if regex.match(_java_concat, arg)

_java_built(_, _, arg) if regex.match(`^\s*String\.format\(`, arg)

_java_built(lines, i, arg) if {
	regex.match(`^\s*[A-Za-z_]\w*\s*$`, arg)
	v := trim_space(arg)
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`\b`, v, `\s*=\s*(?:.*` , _java_concat, `|String\.format\()`]), prev)
	contains(prev, "{")
}
