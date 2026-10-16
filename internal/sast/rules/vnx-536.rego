# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_536

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-536",
	"name": "Servlet Runtime Error Message Containing Sensitive Information",
	"description": "A Java servlet or JSP catches an exception and sends its details to the browser, disclosing class names, SQL text, file paths and library versions. Reported in .java files, inside a catch block (its header may wrap over several lines, as a multi-catch often does) and using the caught variable: e.printStackTrace(...) into the response (response.getWriter(), getOutputStream(), a PrintWriter on it, or a writer variable taken from the response); print/println/printf/write/append/format on response.getWriter()/getOutputStream() or on such a writer of the exception itself or its getMessage()/getLocalizedMessage()/toString()/getStackTrace()/getCause(); and response.sendError(code, <that message>). In .jsp files: <%= exception.getMessage() %> (or getLocalizedMessage/toString/getStackTrace, or the exception itself) and printStackTrace into the page's out writer. Not reported: exceptions logged (log.error, e.printStackTrace() to stderr), generic messages written to the response, values written outside a catch block, comments and test code. Stack traces returned by other frameworks and database errors in general are VNX-209, which leaves the servlet lines reported here to this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-536/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [536],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["servlet", "error-handling", "information-exposure", "cwe-536"],
}

_message := "The caught exception's message or stack trace is written to the HTTP response, telling the client about classes, queries and paths behind the failure. Log the exception on the server and return a generic error (configure an <error-page> in web.xml)"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The variable of the catch block that line i is inside, if any.
_catch_var(lines, i) := v if {
	cs := [j |
		some j in numbers.range(max([0, i - 25]), i - 1)
		regex.match(`\bcatch\s*\(`, lines[j])
	]
	count(cs) > 0
	c := cs[count(cs) - 1]

	# A multi-catch header may wrap: catch (NoSuchAlgorithmException
	#     | InvalidKeyException e) {. Read it up to the line under test.
	hdr := concat(" ", array.slice(lines, c, min([i, c + 8])))
	m := regex.find_all_string_submatch_n(`\bcatch\s*\(\s*(?:final\s+)?[\w.]+(?:\s*\|\s*[\w.]+)*\s+(\w+)\s*\)`, hdr, 1)
	count(m) > 0
	not _closed(lines, c, i)
	v := m[0][1]
}

_closed(lines, c, i) if {
	ic := _indent(lines[c])
	c + 1 <= i - 1
	some k in numbers.range(c + 1, i - 1)
	_indent(lines[k]) <= ic
	startswith(trim_space(lines[k]), "}")
}

# An argument list that carries the exception's details.
_exposes(args, v) if regex.match(concat("", [`(?:^|[^\w.])`, v, `(?:\s*(?:[),+;]|$)|\.(?:getMessage|getLocalizedMessage|toString|getStackTrace|getCause)\s*\()`]), args)

# Writers taken from the response in this file: out = response.getWriter().
_writers(lines) := {m[1] |
	some l in lines
	contains(l, "get")
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*=\s*(?:new\s+PrintWriter\(\s*)?\w+\.get(?:Writer|OutputStream)\(\s*\)`, l, -1)
}

_resp_target(t, ws) if regex.match(`\.get(?:Writer|OutputStream)\(\s*\)`, t)

_resp_target(t, ws) if {
	some w in ws
	regex.match(concat("", [`(?:^|[^\w.])`, w, `\b`]), t)
}

_sink(line, v, ws) if {
	m := regex.find_all_string_submatch_n(concat("", [`\b`, v, `\.printStackTrace\(([^;]*)\)`]), line, 1)
	count(m) > 0
	_resp_target(m[0][1], ws)
}

_sink(line, v, ws) if {
	some m in regex.find_all_string_submatch_n(`((?:\w+\.get(?:Writer|OutputStream)\(\s*\))|\b\w+)\.(?:print|println|printf|write|append|format)\((.*)$`, line, -1)
	_resp_target(m[1], ws)
	_exposes(m[2], v)
}

_sink(line, v, _) if {
	m := regex.find_all_string_submatch_n(`\.sendError\(\s*[^,]+,(.*)$`, line, 1)
	count(m) > 0
	_exposes(m[0][1], v)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "catch")
	regex.match(`get(?:Writer|OutputStream)\(|sendError\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	ws := _writers(lines)
	some i, line in lines
	regex.match(`printStackTrace\(|\.(?:print|println|printf|write|append|format|sendError)\(`, line)
	not helpers.is_comment_line(line)
	v := _catch_var(lines, i)
	_sink(line, v, ws)
	f := _finding(path, i, line)
}

# ── JSP ──────────────────────────────────────────────────────────────────

_jsp_re := `<%=\s*(?:exception|e|ex|err|t)\s*(?:%>|\.(?:getMessage|getLocalizedMessage|toString|getStackTrace|getCause)\s*\()|\b\w+\.printStackTrace\(\s*(?:new\s+(?:java\.io\.)?PrintWriter\(\s*)?out\b`

findings contains f if {
	some path, content in input.file_contents
	some e in {".jsp", ".jspx", ".jspf"}
	endswith(path, e)
	regex.match(_jsp_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_jsp_re, line)
	f := _finding(path, i, line)
}
