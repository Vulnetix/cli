package vulnetix.rules.vnx_go_038

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-038",
	"name": "Potential mass assignment via struct binding",
	"description": "An HTTP handler binds the request body straight into a value and then persists that same value, so a client can set every field the model has, including ones it should never control (role, is_admin, owner, balance). Reported at the bind: json.NewDecoder(r.Body).Decode(&x) (inline, wrapped onto the next line, or through a decoder variable), json.Unmarshal of r.Body or of a body read with io.ReadAll(r.Body), and the framework binders gin ShouldBind*/Bind*, echo c.Bind, fiber c.BodyParser and iris ReadJSON, when x is passed whole to a create/update call within the next 30 lines of the function (GORM Create/Save/Updates/Update/FirstOrCreate, Mongo InsertOne/UpdateOne/ReplaceOne including a bson.M{\"$set\": x} update, a repository Insert/Update/Upsert, with the call's arguments possibly wrapped over several lines). Not reported: a request DTO whose fields are copied into the model (x.Name), a write restricted with GORM Select or Omit, a bound value that is only read (search filters, responses), decoding a response from an API the program calls (resp.Body), test files, comments and string literals. Flows through other functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-038/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["mass-assignment", "struct", "binding"],
}

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The body being read belongs to an incoming request.
_request_body := `\b(?:r|req|request|c\.Request|ctx\.Request)\.Body\b`

_framework_bind := `\b(?:c|ctx)\.(?:ShouldBind\w*|Bind\w*|BodyParser|ReadJSON)\(\s*&?([A-Za-z_]\w*)\s*\)`

_write := `\.(?:Create|Save|Updates|Update|UpdateColumns|FirstOrCreate|Insert|InsertOne|InsertMany|UpdateOne|UpdateByID|ReplaceOne|Upsert)\(`

_word(v) := concat("", [`\b`, v, `\b`])

# The value a line binds the request into.
_target(_, _, code) := v if {
	regex.match(_request_body, code)
	m := regex.find_all_string_submatch_n(`\.Decode\(\s*&?([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
	v := m[0][1]
}

_target(_, _, code) := v if {
	m := regex.find_all_string_submatch_n(`\bjson\.Unmarshal\(\s*[^,]*(?:r|req|request)\.Body[^,]*,\s*&?([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
	v := m[0][1]
}

_target(_, _, code) := v if {
	m := regex.find_all_string_submatch_n(_framework_bind, code, 1)
	count(m) > 0
	v := m[0][1]
}

# dec := json.NewDecoder(r.Body) a few lines up, dec.Decode(&x) here.
_target(lines, i, code) := v if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.Decode\(\s*&?([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
	m[0][1] in helpers.tainted_names(lines, i, 8, `NewDecoder\(\s*(?:http\.MaxBytesReader\([^,]*,\s*)?(?:r|req|request|c\.Request)\.Body\b`)
	v := m[0][2]
}

# body, _ := io.ReadAll(r.Body) a few lines up, json.Unmarshal(body, &x) here.
_target(lines, i, code) := v if {
	m := regex.find_all_string_submatch_n(`\bjson\.Unmarshal\(\s*([A-Za-z_]\w*)\s*,\s*&?([A-Za-z_]\w*)\s*\)`, code, 1)
	count(m) > 0
	m[0][1] in helpers.tainted_names(lines, i, 8, `\b(?:io|ioutil)\.ReadAll\(\s*(?:r|req|request|c\.Request)\.Body\b`)
	v := m[0][2]
}

# The whole value is written to storage later in the function.
_persisted(lines, i, v) if {
	end := min([count(lines) - 1, i + 30])
	end >= i + 1
	some k in numbers.range(i + 1, end)
	not _fn_ended(lines, i, k)
	regex.match(_write, lines[k])
	l := _stmt(lines, k)
	regex.match(_write, l)
	regex.match(concat("", [`[(,:]\s*&?`, v, `\s*[,)}]`]), l)
	not regex.match(`\.(?:Select|Omit)\(`, l)
}

_pdepth(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# A statement's code, joined with up to four following lines while its
# parentheses are open (repo.Update(\n ctx,\n x,\n)) or it ends in a
# method-chain dot (json.NewDecoder(r.Body).\n Decode(&x)).
_stmt(lines, k) := l if {
	l := _code(lines[k])
	_pdepth(l) <= 0
	not endswith(trim_space(l), ".")
}

_stmt(lines, k) := txt if {
	first := _code(lines[k])
	_open(first)
	end := min([count(lines) - 1, k + 4])
	end >= k + 1
	ks := [j |
		some j in numbers.range(k + 1, end)
		not _open(concat(" ", [trim_space(_code(lines[m])) | some m in numbers.range(k, j)]))
	]
	stop := array.concat(ks, [end])[0]
	txt := concat("", [trim_space(_code(lines[m])) | some m in numbers.range(k, stop)])
}

_open(s) if _pdepth(s) > 0

_open(s) if endswith(trim_space(s), ".")

_fn_ended(lines, i, k) if {
	some m in numbers.range(i + 1, k)
	startswith(lines[m], "}")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`\.Body\b|\.(?:ShouldBind|Bind|BodyParser|ReadJSON)`, content)
	regex.match(_write, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Decode(?:r)?\(|Unmarshal\(|Bind|BodyParser\(|ReadJSON\(`, line)
	not helpers.is_comment_line(line)
	code := _stmt(lines, i)
	some v in {t | t := _target(lines, i, code)}
	_persisted(lines, i, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Request body is bound into %s and %s is then saved whole: a client can set any field of the model (mass assignment). Bind into a dedicated input type and copy the allowed fields, or restrict the write with Select/Omit", [v, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
