package vulnetix.rules.vnx_ruby_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUBY-006",
	"name": "Ruby mass assignment",
	"description": "Request parameters reach ActiveRecord attribute assignment without a strong-parameters allowlist: create/create!/update/update!/update_attributes/assign_attributes/attributes=/first_or_create/first_or_initialize/find_or_create_by/find_or_initialize_by/insert_all/upsert(_all) or Model.new given params, params[...], request.params, params.to_unsafe_h or a .permit! result, directly or through a variable assigned from one (up to two assignments, so a reject/merge on the raw hash still counts) in the 15 lines above; every .permit! call; and a .permit(...) list that admits a privilege attribute (admin, is_admin, role, role_id, roles, role_ids, superuser, super_admin, site_admin, permissions, as a symbol or as a nested key such as permissions: []) outside an admin controller, including a list spread over the lines after permit( (reported on the attribute's line). Not reported: values filtered by params.require(...).permit(...) or .slice, a single scalar param (update(name: params[:name])), Model.new(params) with the whole bare params hash (form and service objects), Hash#update on option hashes, OpenStruct/Struct.new, comments and strings. Rails 4+ raises ForbiddenAttributesError for unpermitted ActionController::Parameters, so findings on raw params matter most for Sinatra, Rails 3 and apps that set permit_all_parameters.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-ruby-006/",
	"languages": ["ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["mass-assignment", "activerecord", "authorization"],
}

# An unfiltered request hash: params or a nested params value, the unsafe
# conversions, request.params. A permit(...) or slice(...) filter makes it safe.
_raw_re := `^\s*\(?\s*(?:params(?:\s*\[[^\]]+\])*(?:\.to_unsafe_h(?:ash)?|\.permit!|\.require\([^)]*\)\.permit!|\.to_h)?|request\.(?:params|POST|request_parameters))\s*(?:[,)]|\.(?:merge|except|reject|deep_merge)\b|$)`

_assign_re := `^\s*(@{0,2}[A-Za-z_]\w*)\s*(?:\|\|)?=\s*[^=~>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
}

_rhs(line) := regex.replace(line, `^\s*@{0,2}\w+\s*(?:\|\|)?=\s*`, "")

_ident_re(v) := concat("", [`(?:^|[^\w@:])`, v, `\b`])

_filtered(text) if regex.match(`\.permit\(|\.slice\(|\.require\([^)]*\)\.permit\(`, text)

_tainted(lines, i) := t1 | t2 if {
	i > 0
	lo := max([0, i - 15])
	t1 := {v |
		some j in numbers.range(lo, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(`\bparams\b|request\.(?:params|POST)`, l)
		rhs := _rhs(l)
		rhs != l
		regex.match(_raw_re, regex.replace(rhs, `\s+(?:if|unless)\s.*$`, ""))
		v := _assigned(l)
	}
	t2 := {w |
		some k in numbers.range(lo, i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		w := _assigned(l)
		rhs := _rhs(l)
		not _filtered(rhs)
		some v in t1
		v != w
		regex.match(concat("", [`^\s*`, v, `\b`]), rhs)
	}
}

_tainted(_, 0) := set()

# Attribute-assigning calls. `new` needs a constant receiver.
_call_re := `(?:\.(create!?|update!?|update_attributes!?|assign_attributes|first_or_create!?|first_or_initialize|find_or_create_by!?|find_or_initialize_by|insert_all!?|upsert(?:_all)?|build)|\.(attributes)\s*=|\b([A-Z][\w:]*)\.(new))\s*(?:\(\s*|\s+)`

# Hash#update and value objects take a hash too.
_not_model(code, at) if {
	prefix := substring(code, 0, at)
	regex.match(`(?i)(?:\b(?:opts|options|hash|h|params|settings|config|headers|defaults|query|env|attrs|meta|data|result|session|cookies|flash)|\]|\})\s*$`, prefix)
}

_value_class(cls) if regex.match(`^(?:OpenStruct|Struct|Hash|Set|Array|String|Thread|Proc|URI(?:::\w+)?|ActionController::Parameters|ActiveSupport::\w+|Rack::\w+)$`, cls)

_unfiltered(lines, i, args) if {
	not _filtered(args)
	regex.match(_raw_re, args)
}

_unfiltered(lines, i, args) if {
	not _filtered(args)
	m := regex.find_all_string_submatch_n(`^\s*\(?\s*(@{0,2}[a-z_]\w*)\s*(?:[,)]|\.(?:merge|except|reject)\b|$)`, args, 1)
	count(m) > 0
	m[0][1] in _tainted(lines, i)
}

_priv_names := `admin|is_admin|role|role_id|roles|role_ids|superuser|super_admin|site_admin|permissions|permission_ids`

# :admin as a symbol, or permissions: [] / roles: [] as a nested permit key.
_privileged_re := concat("", [`:(?:`, _priv_names, `)\b|(?:^|[\s,(])(?:`, _priv_names, `):\s`])

# A permit( list left open on its line continues on the next lines; each
# privilege attribute is reported on its own line.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	not _admin_path(path)
	contains(content, ".permit(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".permit(")
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(`\.permit\([^)]*$`, code)
	_outside_string(code, ".permit(")
	some k in numbers.range(1, 12)
	j := i + k
	j < count(lines)
	l := _code(lines[j])
	regex.match(_privileged_re, l)
	not helpers.is_comment_line(lines[j])
	count([n | some n in numbers.range(i + 1, j); n < j; contains(_code(lines[n]), ")")]) == 0
	finding := _finding(path, j, lines[j], "Strong parameters permit a privilege attribute (admin/role/permissions) from the request, letting users grant themselves rights; set it only from an authorised admin action")
}

_admin_path(path) if regex.match(`(?:^|/)admin/|admin\w*_controller\.rb$`, path)

_outside_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	stripped := regex.replace(prefix, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, "")
	not contains(stripped, `"`)
	not contains(stripped, "'")
}

_code(line) := regex.replace(line, `\s#[^{].*$`, "")

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_gate(content) if regex.match(`\bparams\b|request\.(?:params|POST)`, content)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`create|update|assign_attributes|attributes|first_or_|find_or_|insert_all|upsert|build|\.new\b`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some m in regex.find_all_string_submatch_n(_call_re, code, -1)
	at := indexof(code, m[0])
	_outside_string(code, m[0])
	not _not_model(code, at)
	not _value_class(m[3])
	args := substring(code, at + count(m[0]), -1)
	_new_ok(m[4], args)
	_unfiltered(lines, i, args)
	finding := _finding(path, i, line, "Request parameters are assigned to a model without a strong-parameters allowlist; pass params.require(:model).permit(:field, ...) instead")
}

# Model.new(params) with the bare hash is usually a form or service object.
_new_ok(kind, _) if kind != "new"

_new_ok("new", args) if not regex.match(`^\s*\(?\s*params\s*(?:[,)]|$)`, args)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	contains(content, "permit!")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "permit!")
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(`\.permit!`, code)
	_outside_string(code, ".permit!")
	finding := _finding(path, i, line, "params.permit! allows every request attribute through strong parameters; list the permitted fields with permit(:field, ...)")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rb")
	not _admin_path(path)
	contains(content, ".permit(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".permit(")
	not helpers.is_comment_line(line)
	code := _code(line)
	some m in regex.find_all_string_submatch_n(`\.permit\(([^)]*)\)?`, code, -1)
	regex.match(_privileged_re, m[1])
	_outside_string(code, m[0])
	finding := _finding(path, i, line, "Strong parameters permit a privilege attribute (admin/role/permissions) from the request, letting users grant themselves rights; set it only from an authorised admin action")
}
