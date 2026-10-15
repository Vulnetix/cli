# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_600

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-600",
	"name": "Servlet parses request input with no handler for the exception",
	"description": "A servlet handler (doGet, doPost, doPut, doDelete, doHead, doOptions, doTrace or service taking an HttpServletRequest), or a JSP scriptlet, converts a request parameter, header, query string or path into a number, decimal, UUID or date (Integer/Long/Short/Double/Float parse or valueOf, new BigDecimal, new BigInteger, UUID.fromString, LocalDate/LocalDateTime/Instant.parse) outside any try block. Any malformed value throws a NumberFormatException, IllegalArgumentException or DateTimeParseException out of the servlet, which the container turns into a 500 page that can carry a stack trace and internal details, and which an attacker can trigger at will. The argument is the request read itself or a variable assigned from one within the 15 lines above that was not first checked for format (v.matches(..), isNumeric/isDigits/isCreatable(v), pattern.matcher(v).matches()). Not reported: conversions inside a try block, in a helper method that handles the exception, of constants or of non-request data (properties, argv), code outside servlet handlers, comments and string literals. Exceptions thrown by deeper calls are not traced.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-600/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [600],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["java", "servlet", "exception-handling", "error-handling", "cwe-600"],
}

_parser := `(?:\b(?:Integer|Long|Short|Byte|Double|Float)\s*\.\s*(?:parse\w*|valueOf)|\bnew\s+(?:BigDecimal|BigInteger)|\bUUID\s*\.\s*fromString|\b(?:LocalDate|LocalDateTime|LocalTime|Instant|ZonedDateTime|OffsetDateTime)\s*\.\s*parse)\s*\(`

_source := `\.(?:getParameter|getHeader|getQueryString|getPathInfo|getRequestURI|getParameterValues|getAttribute)\s*\(`

_handler_re := `\b(?:doGet|doPost|doPut|doDelete|doHead|doOptions|doTrace|service)\s*\(`

_method_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized)\s+)+[\w<>\[\],.? ]+\s+\w+\s*\(`

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_msg := "A request value is converted to a number, UUID or date outside any try block in a servlet; a malformed value throws out of the servlet and the container answers with a 500 page that can expose a stack trace. Catch the exception and return 400"

findings contains finding if {
	some path, content in input.file_contents
	_kind(path, content)
	regex.match(_parser, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_parser, c)
	_from_request(lines, i, c)
	start := _scope_start(path, lines, i)
	not _in_try(lines, start, i)
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

_kind(path, content) if {
	endswith(path, ".java")
	contains(content, "HttpServletRequest")
}

_kind(path, _) if endswith(path, ".jsp")

_kind(path, _) if endswith(path, ".jspx")

# The request read is the argument of the conversion.
_from_request(_, _, c) if {
	regex.match(concat("", [_parser, `[^;]*`, _source]), c)
}

# Or a variable assigned from one a few lines up.
_from_request(lines, i, c) if {
	some v in helpers.tainted_names(lines, i, 15, _source)
	regex.match(concat("", [_parser, `\s*`, v, `\s*(?:\.\s*\w+\s*\(\s*\)\s*)?[,)]`]), c)
	not _validated(lines, i, v)
}

# The variable was checked for format first (id.matches("\\d+"),
# StringUtils.isNumeric(id), NumberUtils.isDigits(id), pattern.matcher(id).matches()).
_validated(lines, i, v) if {
	some k in numbers.range(max([0, i - 15]), i - 1)
	regex.match(concat("", [`\b`, v, `\s*\.\s*matches\s*\(|\bis(?:Numeric|Digits|Creatable|Parsable)\s*\(\s*`, v, `\s*\)|\.matcher\s*\(\s*`, v, `\s*\)\s*\.\s*matches\s*\(`]), lines[k])
}

# Java: the enclosing method must be a servlet handler; its declaration line
# is where the try search starts.
_scope_start(path, lines, i) := s if {
	endswith(path, ".java")
	cands := [k |
		some k in numbers.range(max([0, i - 150]), i)
		regex.match(_method_re, lines[k])
	]
	count(cands) > 0
	s := max(cands)
	regex.match(_handler_re, lines[s])
	_takes_request(lines, s)
}

_scope_start(path, lines, i) := max([0, i - 60]) if {
	not endswith(path, ".java")
}

_takes_request(lines, s) if {
	some k in numbers.range(s, min([count(lines) - 1, s + 2]))
	contains(lines[k], "HttpServletRequest")
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A try opened above line i (after the scope start) whose block is still open.
_in_try(lines, start, i) if {
	some k in numbers.range(start, i - 1)
	regex.match(`^\s*(?:\}\s*)?try\b`, lines[k])
	ik := _indent(lines[k])
	_indent(lines[i]) > ik
	not _closed(lines, k, i, ik)
}

_closed(lines, k, i, ik) if {
	k + 1 <= i - 1
	some m in numbers.range(k + 1, i - 1)
	_indent(lines[m]) <= ik
	startswith(trim_left(lines[m], " \t"), "}")
}
