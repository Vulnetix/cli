# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_248

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-248",
	"name": "Request input parsed without catching the parse exception",
	"description": "A request parameter, header or body is converted with a parser that throws on malformed text, and nothing around the call catches the exception, so any client can make the handler fail with an uncaught exception (an HTTP 500, often with a stack trace, or an aborted operation). Reported in Java: Integer.parseInt/valueOf, Long.parseLong/valueOf, Short.parseShort, Byte.parseByte, Double.parseDouble, Float.parseFloat, UUID.fromString, LocalDate/LocalDateTime/LocalTime/Instant/ZonedDateTime/OffsetDateTime.parse, new BigDecimal and new BigInteger applied to request.getParameter()/getHeader() directly (optionally trimmed), to a variable assigned from one a few lines above, or to a String parameter bound with Spring @RequestParam/@PathVariable/@RequestHeader/@CookieValue or JAX-RS @QueryParam/@PathParam/@HeaderParam/@FormParam/@CookieParam/@MatrixParam. In Python: int(), float(), Decimal(), uuid.UUID(), json.loads() and date/datetime.fromisoformat()/strptime() applied to request.args/form/values/GET/POST/COOKIES/META/data/json/headers/cookies/query_params directly or through a variable assigned from them. A try whose only handler is for an unrelated exception (IOException, KeyError) does not count as catching the parse error. Not reported: a call inside a try block whose catch/except covers the parse error (NumberFormatException, IllegalArgumentException, RuntimeException, Exception, Throwable; ValueError, TypeError, JSONDecodeError, Exception or a bare except), a variable or request expression checked first (isdigit/isnumeric/fullmatch/re.match, matches(), NumberUtils/StringUtils checks) or in an inline conditional (int(raw) if raw.isdigit() else 0), a value derived from the input rather than the input itself (int(len(request.data))), a Java file with an @ExceptionHandler or a project with @ControllerAdvice/@RestControllerAdvice, Flask's request.args.get(..., type=int), parsing of constants, configuration or system properties, comments, strings and test code. Exceptions thrown by deeper calls are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-248/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [248],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "denial-of-service", "cwe-248"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# One level of nested parentheses inside the argument list.
_args := `\(\s*([^()]*(?:\([^()]*\)[^()]*)*)\)`

_java_sink := concat("", [`\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Short\.parseShort|Byte\.parseByte|Double\.(?:parseDouble|valueOf)|Float\.(?:parseFloat|valueOf)|UUID\.fromString|(?:LocalDate|LocalDateTime|LocalTime|Instant|ZonedDateTime|OffsetDateTime)\.parse|new\s+BigDecimal|new\s+BigInteger)\s*`, _args])

_py_sink := concat("", [`(?:^|[^\w.])(?:int|float|Decimal|uuid\.UUID|UUID|json\.loads|(?:datetime\.)?(?:datetime|date)\.(?:fromisoformat|strptime))\s*`, _args])

_java_source := `\.(?:getParameter|getHeader)\s*\(`

_py_source := `\brequest\.(?:args|form|values|GET|POST|data|json|headers|cookies|COOKIES|META|query_params|body)\b`

_guard := `(?i)isdigit|isnumeric|isdecimal|fullmatch|re\.match|\.matches\s*\(|isDigits|isNumeric|isCreatable|isParsable|tryParse`

_lang("java", path) if endswith(path, ".java")

_lang("python", path) if endswith(path, ".py")

_sink_re("java") := _java_sink

_sink_re("python") := _py_sink

_source_re("java") := _java_source

_source_re("python") := _py_source

_file_source_re("java") := `\.(?:getParameter|getHeader)\s*\(|@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|PathParam|HeaderParam|FormParam|CookieParam|MatrixParam)\b`

_file_source_re("python") := _py_source

# Spring handler parameters bound from the request, in the signature above.
_bound_params(lines, i) := {v |
	some j in numbers.range(max([0, i - 20]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|PathParam|HeaderParam|FormParam|CookieParam|MatrixParam)(?:\s*\([^)]*\))?\s+(?:final\s+)?String\s+(\w+)`, lines[j], -1)
	v := m[1]
}

# The argument is the request value itself (possibly trimmed), not a value
# derived from it such as len(request.data).
_direct_re("java") := `^[\w\.]*\.(?:getParameter|getHeader)\s*\(`

_direct_re("python") := `^\(?\s*request\.`

_tainted(lang, lines, i, arg) if {
	regex.match(_direct_re(lang), arg)
	not _guarded_direct(lines, i, arg)
}

# The same request expression was validated in the few lines above.
_guarded_direct(lines, i, arg) if {
	some k in numbers.range(max([0, i - 6]), i - 1)
	regex.match(_guard, lines[k])
	contains(lines[k], _source_call(arg))
}

_source_call(arg) := c if {
	m := regex.find_all_string_submatch_n(`^[^)]*\)`, arg, 1)
	count(m) > 0
	c := m[0][0]
} else := arg

_tainted(lang, lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source_re(lang), prev)
	helpers.assigned_first(prev) == arg
	not regex.match(`type\s*=`, prev)
	not _guarded(lines, j, i, arg)
	not _inline_guard(lines[i], arg)
}

# n = int(raw) if raw.isdigit() else 0
_inline_guard(line, arg) if {
	regex.match(_guard, line)
	contains(line, concat("", [arg, "."]))
}

_tainted("java", lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	arg in _bound_params(lines, i)
	not _guarded(lines, max([0, i - 20]), i, arg)
}

_guarded(lines, j, i, arg) if {
	some k in numbers.range(j, i - 1)
	contains(lines[k], arg)
	regex.match(_guard, lines[k])
}

# The innermost try block above i that still encloses it.
_try_re("java") := `^\s*(?:\}\s*)?try\b`

_try_re("python") := `^\s*try\s*:`

_catch_re("java") := `^\s*\}?\s*catch\s*\(([^)]*)\)`

_catch_re("python") := `^\s*except\b\s*([^:]*):`

_covers("java", t) if regex.match(`\b(NumberFormatException|IllegalArgumentException|RuntimeException|Exception|Throwable|DateTimeParseException)\b`, t)

_covers("python", t) if trim_space(t) == ""

_covers("python", t) if regex.match(`\b(ValueError|TypeError|JSONDecodeError|Exception|BaseException|InvalidOperation)\b`, t)

_open_try(lang, lines, i) := k if {
	ii := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 60]), i - 1)
		regex.match(_try_re(lang), lines[k])
		_indent(lines[k]) < ii
		not _closed(lines, k, i)
	]
	count(ks) > 0
	k := max(ks)
}

_closed(lines, k, i) if {
	ik := _indent(lines[k])
	k + 1 <= i - 1
	some m in numbers.range(k + 1, i - 1)
	trim_space(lines[m]) != ""
	_indent(lines[m]) <= ik
}

_caught(lang, lines, i) if {
	k := _open_try(lang, lines, i)
	ik := _indent(lines[k])
	some m in numbers.range(i + 1, min([count(lines) - 1, i + 80]))
	_indent(lines[m]) == ik
	cm := regex.find_all_string_submatch_n(_catch_re(lang), lines[m], 1)
	count(cm) > 0
	_covers(lang, cm[0][1])
}

# An @ExceptionHandler for the parse exception or one of its supertypes.
_handler_re := `@ExceptionHandler\s*\([^)]*\b(?:NumberFormatException|IllegalArgumentException|RuntimeException|Exception|Throwable|MethodArgumentTypeMismatchException)\.class`

_advice_project if {
	some p, c in input.file_contents
	endswith(p, ".java")
	regex.match(`@(?:Rest)?ControllerAdvice\b`, c)
	regex.match(_handler_re, c)
}

_handled_file("java", content) if regex.match(_handler_re, content)

_handled_file("java", _) if _advice_project

_handled_file("python", content) if regex.match(`errorhandler\(\s*(ValueError|Exception|500)`, content)

findings contains finding if {
	some path, content in input.file_contents
	some lang in {"java", "python"}
	_lang(lang, path)
	not helpers.is_test_path(path)
	regex.match(_file_source_re(lang), content)
	regex.match(`(?m)(parse|valueOf|fromString|Big|int\(|float\(|Decimal\(|UUID\(|loads\(|fromisoformat|strptime)`, content)
	not _handled_file(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_sink_re(lang), line, -1)
	arg := trim_space(m[1])
	_tainted(lang, lines, i, arg)
	not _in_string(line, m[0])
	not _caught(lang, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Request input is parsed with a call that throws on malformed text and nothing catches the exception; validate the value or catch the parse error and answer 400",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The match sits inside a string literal: an odd number of quotes before it.
_in_string(line, match) if {
	idx := indexof(line, match)
	idx > 0
	before := substring(line, 0, idx)
	q := count(regex.find_all_string_submatch_n(`"`, before, -1))
	q % 2 == 1
}
