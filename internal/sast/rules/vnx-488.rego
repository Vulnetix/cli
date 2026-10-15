# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_488

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-488",
	"name": "Exposure of Data Element to Wrong Session",
	"description": "Per-request or per-user data stored in a field of a Java component that one instance serves every request: a class that extends HttpServlet/GenericServlet, is annotated @WebServlet, @Controller or @RestController, or extends a Struts Action. A request handler assigns a non-final field (instance or static) from the request (getParameter, getHeader, getAttribute, getSession, getRemoteUser, getUserPrincipal, getCookies, getInputStream/getReader, getQueryString), directly or through a local variable assigned from the request a few lines above. Concurrent requests share the field, so one user's data is served to another. Not reported: locals, final fields, assignments in init() or a constructor, fields of classes that are not request singletons (including Spring beans annotated @RequestScope, @SessionScope or @Scope request/session/prototype), fields set from servlet configuration, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-488/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [488],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["servlet", "shared-state", "session", "race-condition", "cwe-488"],
}

_singleton_re := `(?m)\bextends\s+(?:Http|Generic)Servlet\b|^\s*@(?:WebServlet|Controller|RestController)\b|\bextends\s+(?:Action|DispatchAction|MappingDispatchAction)\b`

# A Spring bean given a narrower scope gets a fresh instance per request,
# session or injection, so its fields are not shared across users.
_scoped_bean_re := `(?m)^\s*@(?:RequestScope|SessionScope|Scope\s*\(\s*(?:(?:value|scopeName)\s*=\s*)?(?:"(?:request|session|prototype)"|(?:WebApplicationContext|ConfigurableBeanFactory)\s*\.\s*SCOPE_(?:REQUEST|SESSION|PROTOTYPE)))\b`

_request_re :=`\b\w*(?:request|req|Request|Req)\w*\s*\.\s*(?:getParameter(?:Values|Map)?|getHeader|getHeaders|getAttribute|getSession|getRemoteUser|getUserPrincipal|getCookies|getInputStream|getReader|getQueryString|getPathInfo|getPart)\s*\(`

# A member-level field declaration (no `final`, not a method): the name.
_field_decl_re := `^([ \t]+)(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:private|protected|public|static|volatile|transient)\s+)*[A-Za-z_][\w.]*(?:<[^;=()]*>)?(?:\s*\[\])*\s+([A-Za-z_]\w*)\s*(?:=[^=][^;]*)?;\s*(?://.*)?$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# Member indent: the first code line after the first class declaration.
_member_indent(lines) := ind if {
	decls := [j | some j, l in lines; regex.match(`^(?:\S.*\s)?class\s+\w+`, l); not helpers.is_comment_line(l)]
	count(decls) > 0
	d := decls[0]
	body := [j |
		some j in numbers.range(d + 1, min([count(lines) - 1, d + 40]))
		trim_space(lines[j]) != ""
		trim_space(lines[j]) != "{"
		not helpers.is_comment_line(lines[j])
	]
	count(body) > 0
	ind := _indent(lines[body[0]])
}

_fields(lines, ind) := {name |
	some l in lines
	not contains(l, "(")
	not regex.match(`\bfinal\b`, l)
	not regex.match(`^\s*(?:return|throw|package|import)\b`, l)
	m := regex.find_all_string_submatch_n(_field_decl_re, l, 1)
	count(m) > 0
	count(m[0][1]) == ind
	name := m[0][2]
}

# The enclosing method declaration of line i: the nearest line above at
# member indent that opens a method.
_enclosing_method(lines, i, ind) := lines[k] if {
	ks := [k |
		some k in numbers.range(max([0, i - 200]), i - 1)
		k < i
		_indent(lines[k]) == ind
		contains(lines[k], "(")
		not helpers.is_comment_line(lines[k])
		not startswith(trim_space(lines[k]), "@")
	]
	count(ks) > 0
	k := ks[count(ks) - 1]
}

_setup_method(sig) if regex.match(`\b(?:init|destroy|setUp|afterPropertiesSet|postConstruct)\s*\(`, sig)

_setup_method(sig) if regex.match(`^\s*(?:public|protected|private)?\s*[A-Z]\w*\s*\(`, sig)

_tainted_rhs(_, _, rhs) if regex.match(_request_re, rhs)

_tainted_rhs(lines, i, rhs) if {
	some v in helpers.tainted_names(lines, i, 6, _request_re)
	regex.match(concat("", [`^\s*\(?\s*(?:\([\w.<>]+\)\s*)?`, v, `\b`]), rhs)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_singleton_re, content)
	not regex.match(_scoped_bean_re, content)
	contains(content, "Request")
	lines := split(content, "\n")
	ind := _member_indent(lines)
	fields := _fields(lines, ind)
	count(fields) > 0
	some i, line in lines
	_indent(line) > ind
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*=([^=].*)$`, _code(line), 1)
	count(m) > 0
	fields[m[0][1]]
	_tainted_rhs(lines, i, m[0][2])
	sig := _enclosing_method(lines, i, ind)
	not _setup_method(sig)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Request data stored in field '%s' of a component that one instance serves every request; concurrent users read each other's value. Keep it in a local variable or the request/session", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
