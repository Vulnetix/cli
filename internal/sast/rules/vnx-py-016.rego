package vulnetix.rules.vnx_py_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-016",
	"name": "Django mass assignment via request data unpacking",
	"description": "The whole request body reaches a model's fields: unpacked with ** (request.data, request.POST/GET, request.json/form/args/values, request.get_json(), json.loads(request.body), or a variable assigned from one of them) into Model.objects.create/get_or_create/update_or_create, a queryset .update(), a SQLAlchemy insert()/update() .values(), or a model constructor in a file that uses an ORM; passed as the dict of a SQLAlchemy Query .filter()/.filter_by()/.where() ... .update(<body>); copied onto an object with obj.__dict__.update() or vars(obj).update(); or written field by field with setattr() in a loop over the request keys with no allowlist check. Also reported: a DRF ModelSerializer or Django ModelForm whose Meta sets fields = \"__all__\" without making them read-only. An attacker can then set is_staff, role, price or any other column. Not reported: explicit keyword arguments, a dict built from an allowlist, serializer.validated_data or form.cleaned_data, pydantic or dataclass constructors, a setattr loop guarded by a membership test, and comments or strings that mention the pattern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-016/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-78"],
	"attack_technique": ["T1565"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["mass-assignment", "django", "python"],
}

_is_py(path) if endswith(path, ".py")

# The whole request body, as an expression.
_src := `(?:await\s+)?(?:request\.(?:data|POST|GET|json|form|args|values|query_params)(?:\.(?:dict|to_dict|copy)\(\))?|request\.get_json\([^)]*\)|request\.json\(\)|json\.loads\(\s*request\.(?:body|data|get_data\(\))\s*\))`

_src_full := concat("", [`^`, _src, `$`])

# Names assigned exactly the request body (not a comprehension or a lookup of
# one key) in the lines above i.
_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*([A-Za-z_]\w*)\s*=\s*`, _src, `\s*(?:#.*)?$`]), lines[j], 1)
	count(m) > 0
	v := m[0][1]
}

_bad_expr(expr, _, _) if regex.match(_src_full, trim_space(expr))

_bad_expr(expr, lines, i) if {
	e := trim_space(expr)
	regex.match(`^[A-Za-z_]\w*(?:\.(?:items|keys)\(\))?$`, e)
	name := split(e, ".")[0]
	name in _tainted(lines, i)
}

# A loop over the body itself or over its .items()/.keys().
_bad_iter(expr, lines, i) if _bad_expr(expr, lines, i)

_bad_iter(expr, lines, i) if {
	e := trim_space(expr)
	regex.match(`\.(?:items|keys)\(\)$`, e)
	_bad_expr(regex.replace(e, `\.(?:items|keys)\(\)$`, ""), lines, i)
}

# An odd number of quotes before the match: it is inside a string.
_in_string(prefix) if count(split(prefix, "\"")) % 2 == 0

_in_string(prefix) if count(split(prefix, "'")) % 2 == 0

_expr := `((?:await\s+)?[A-Za-z_][\w.]*(?:\([^()]*\))?(?:\.\w+\(\))?|json\.loads\(\s*request\.\w+(?:\(\))?\s*\))`

# ** into a manager create, a queryset update, or a constructor.
_orm_sink := concat("", [`^(.*?)(?:(\.objects\.(?:create|get_or_create|update_or_create)|\.(?:objects|all\(\)|filter\([^)]*\)|exclude\([^)]*\))\.update|\b[A-Z]\w*)\s*\(.*?|(\.values)\s*\(\s*)\*\*\s*`, _expr])

_orm_file(content) if regex.match(`(?m)db\.session|session\.add\(|\.save\(\)|sqlalchemy|django\.db|\.objects\.|from\s+\S*models\s+import`, content)

# A constructor is a model only when the file uses an ORM and does not declare
# the class as a validation schema.
_sink_ok(callee, _) if startswith(callee, ".")

_sink_ok(callee, content) if {
	not startswith(callee, ".")
	_orm_file(content)
	not regex.match(concat("", [`(?m)^\s*class\s+`, callee, `\s*\([^)]*(?:BaseModel|Schema|TypedDict|NamedTuple)`]), content)
	not regex.match(concat("", [`(?m)^@dataclass[^\n]*\n\s*class\s+`, callee, `\b`]), content)
}

_message := "The whole request body is written to a model's fields (mass assignment); an attacker can set is_staff, role, price or any other column. Copy only an explicit allowlist of fields, or use a serializer or form with explicit fields."

findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	contains(content, "**")
	contains(content, "request")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "**")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_orm_sink, line, 1)
	count(m) > 0
	not _in_string(m[0][1])
	_sink_ok(concat("", [m[0][2], m[0][3]]), content)
	_bad_expr(m[0][4], lines, i)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	regex.match(`__dict__\.update|vars\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^(.*?)(?:\.__dict__|\bvars\([^)]*\))\.update\(\s*`, _expr]), line, 1)
	count(m) > 0
	not _in_string(m[0][1])
	_bad_expr(m[0][2], lines, i)
	finding := _finding(path, i, line)
}

# setattr(obj, key, ...) inside `for key[, value] in <request body>:` with no
# test of the key in between.
findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	contains(content, "setattr(")
	contains(content, "request")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setattr(")
	not helpers.is_comment_line(line)
	sm := regex.find_all_string_submatch_n(`^\s*setattr\(\s*[\w.]+\s*,\s*([A-Za-z_]\w*)\s*,`, line, 1)
	count(sm) > 0
	key := sm[0][1]
	i > 0
	some j in numbers.range(max([0, i - 4]), i - 1)
	fm := regex.find_all_string_submatch_n(concat("", [`^\s*for\s+\(?\s*`, key, `\b(?:\s*,\s*\w+)?\s*\)?\s+in\s+(.+?)\s*:\s*$`]), lines[j], 1)
	count(fm) > 0
	_bad_iter(fm[0][1], lines, j)
	not _guarded(lines, j, i, key)
	finding := _finding(path, i, line)
}

_guarded(lines, j, i, key) if {
	some k in helpers.span(j + 1, i - 1)
	regex.match(concat("", [`^\s*(?:if|elif)\b.*\b`, key, `\b`]), lines[k])
}

# fields = "__all__" in the Meta of a ModelSerializer or ModelForm.
findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	contains(content, "__all__")
	regex.match(`(?m)^\s*class\s+\w+\s*\([^)]*(?:ModelSerializer|ModelForm)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*fields\s*=\s*["']__all__["']\s*(?:#.*)?$`, line)
	_in_model_meta(lines, i)
	not _read_only_all(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "This ModelSerializer/ModelForm accepts every model field from the client (fields = \"__all__\"), including is_staff, owner or price; list the writable fields explicitly.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_in_model_meta(lines, i) if {
	some j in numbers.range(max([0, i - 6]), i - 1)
	regex.match(`^\s*class\s+Meta\b`, lines[j])
	some k in numbers.range(max([0, j - 3]), j - 1)
	regex.match(`^\s*class\s+\w+\s*\([^)]*(?:ModelSerializer|ModelForm)\b`, lines[k])
}

_read_only_all(lines, i) if {
	some k in numbers.range(max([0, i - 6]), min([count(lines) - 1, i + 6]))
	regex.match(`^\s*read_only_fields\s*=\s*(?:fields\b|["']__all__["'])`, lines[k])
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# SQLAlchemy Query.update(<request body>): the dict maps column names to values
# without any ** unpacking.
_query_update := concat("", [`^(.*?)\.query(?:\([^()]*\))?(?:\.(?:filter|filter_by|where)\((?:[^()]|\([^()]*\))*\))+\.update\(\s*`, _expr, `\s*[,)]`])

findings contains finding if {
	some path, content in input.file_contents
	_is_py(path)
	contains(content, ".update(")
	contains(content, "request")
	contains(content, "query")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".update(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_query_update, line, 1)
	count(m) > 0
	not _in_string(m[0][1])
	_bad_expr(m[0][2], lines, i)
	finding := _finding(path, i, line)
}
