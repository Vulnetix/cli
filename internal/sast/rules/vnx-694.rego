# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_694

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-694",
	"name": "Two route handlers registered under the same identifier",
	"description": "Two handlers are registered for the same route in one Python file, so the URL dispatcher only ever reaches one of them and the other (often the version that adds an authorisation check) is dead code that reviewers believe is live. Reported, at the second and later registration: a Flask/FastAPI/Starlette route decorator (@app.route, @bp.route, @router.get/post/put/patch/delete/head/options, @app.api_route, @app.websocket) on the same receiver with the same arguments (path, methods and options compared with quotes and spacing normalised) as an earlier one in the file, and a Django path()/re_path()/url() entry with the same route string as an earlier entry. Not reported: the same path with different methods (@app.route('/login', methods=['GET']) and methods=['POST'], @app.get and @app.post), the same path on different routers or blueprints, repeated include() prefixes in Django urlpatterns, registrations in different files, test files, comments and string literals. Django entries are compared within one pattern list (urlpatterns = [...] and urlpatterns += [...] are one list; api_patterns = [...] is another, since it is include()d under its own prefix). A trailing comment after a decorator is ignored. Decorators broken over several lines are not compared.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-694/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [694],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["duplicate-identifier", "routing", "cwe-694"],
}

_gate := `(?m)^\s*(?:@\w+\.(?:route|get|post|put|patch|delete|head|options|api_route|websocket)\(|(?:re_)?path\(|url\()`

_deco := `^\s*@(\w+)\.(route|get|post|put|patch|delete|head|options|api_route|websocket)\((.*)\)\s*$`

_django := `^\s*(re_path|path|url)\(\s*r?(?:"([^"]*)"|'([^']*)')\s*,`

_norm(s) := regex.replace(replace(s, "'", "\""), `\s+`, "")

_key(line) := k if {
	# a trailing comment after the decorator: @app.route("/x")  # legacy
	m := regex.find_all_string_submatch_n(_deco, regex.replace(line, `\)\s+#[^"']*$`, ")"), 1)
	count(m) > 0
	k := concat("|", ["deco", m[0][1], m[0][2], _norm(m[0][3])])
}

_key(line) := k if {
	not contains(line, "include(")
	m := regex.find_all_string_submatch_n(_django, line, 1)
	count(m) > 0
	route := concat("", [m[0][2], m[0][3]])
	kind := _django_kind(m[0][1])
	k := concat("|", ["django", kind, route])
}

# A Django entry belongs to the pattern list it is written in: the same route
# in api_patterns and urlpatterns is two URLs once api_patterns is include()d
# under a prefix. urlpatterns = [...] and urlpatterns += [...] are one list.
_scoped(_, _, k) := k if startswith(k, "deco|")

_scoped(lists, i, k) := concat("|", [k, name]) if {
	startswith(k, "django|")
	above := [l[1] | some l in lists; l[0] <= i]
	count(above) > 0
	name := above[count(above) - 1]
}

_scoped(lists, i, k) := k if {
	startswith(k, "django|")
	count([l | some l in lists; l[0] <= i]) == 0
}

_django_kind("path") := "path"

_django_kind("re_path") := "re"

_django_kind("url") := "re"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	quotes := [[j, n] | some j, l in lines; contains(l, `"""`); n := count(indexof_n(l, `"""`))]
	lists := [[j, m[0][1]] |
		some j, l in lines
		contains(l, "=")
		m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*\+?=\s*(?:\[|\w+\()`, l, 1)
		count(m) > 0
	]
	entries := [[i, k] |
		some i, l in lines
		regex.match(`^\s*(?:@|re_path\(|path\(|url\()`, l)
		k0 := _key(l)
		k := _scoped(lists, i, k0)
		not _in_docstring(quotes, i)
	]
	some e in entries
	some prev in entries
	prev[1] == e[1]
	prev[0] < e[0]
	first := min([p[0] | some p in entries; p[1] == e[1]])
	first == prev[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This route is already registered on line %d of the same file; only one of the two handlers is ever dispatched", [first + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": e[0] + 1,
		"snippet": lines[e[0]],
	}
}

# A line inside a """ string (a docstring example): an odd number of triple
# quotes above it.
_in_docstring(quotes, i) if {
	n := sum([q[1] | some q in quotes; q[0] < i])
	n % 2 == 1
}
