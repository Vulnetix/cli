# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_652

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-652",
	"name": "XQuery injection",
	"description": "An XQuery expression built from a non-constant value and handed to an XQuery engine in Java, so whoever controls the value rewrites the query (CWE-652). Only files that use an XQuery API are read: XQJ (javax.xml.xquery), Saxon s9api (net.sf.saxon), BaseX (org.basex), XML:DB/eXist (org.xmldb, XQueryService) and MarkLogic XCC (com.marklogic.xcc). Reported sinks: executeQuery, prepareExpression, executeCommand, compile, query, execute, newAdhocQuery, new XQuery(...) and new QueryProcessor(...) whose argument concatenates a variable, a parameter or a method result into a string literal, uses String.format/formatted/MessageFormat.format, or is a variable (or StringBuilder.toString()) built that way in the ten lines above, including a concatenation broken across lines. Not reported: external variables bound with bindString/bindObject (declare variable ... external), constant queries and concatenation of literals or UPPER_CASE constants, SQL text passed to JDBC executeQuery (inline or through a variable built from SELECT/INSERT/UPDATE/DELETE text), Pattern.compile, a call whose argument is a new object other than XQuery/QueryProcessor (http.execute(new HttpGet(url + ...))), files that use no XQuery API, comments and the call written inside a string literal.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-652/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [652],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xquery", "injection", "cwe-652"],
}

_api := `javax\.xml\.xquery|net\.sf\.saxon|org\.basex|org\.xmldb|com\.marklogic\.xcc|XQueryService`

_sink := `(?:\.(?:executeQuery|prepareExpression|executeCommand|compile|query|execute|newAdhocQuery)|\bnew\s+(?:XQuery|QueryProcessor))\s*\((.*)$`

# A string literal joined with something that is not a literal or an
# UPPER_CASE constant: a variable, a parameter, a method result.
_concat := `"\s*\+\s*[a-z_]|(?:^|[^\w."])[a-z_][\w.]*(?:\([^()]*\))?\s*\+\s*"`

_format := `\bString\.format\s*\(|\.formatted\s*\(|MessageFormat\.format\s*\(`

_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# The argument text of the call: the rest of the line, or the next line when
# the call breaks after its open parenthesis.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# A line joined with the next one when it ends with a `+` continuation.
_joined(lines, j) := concat("\n", [lines[j], lines[j + 1]]) if {
	endswith(trim_right(lines[j], " \t"), "+")
	j + 1 < count(lines)
}

_joined(lines, j) := concat("\n", [lines[j], lines[j + 1]]) if {
	not endswith(trim_right(lines[j], " \t"), "+")
	_next_leads_plus(lines, j)
}

_joined(lines, j) := lines[j] if {
	not endswith(trim_right(lines[j], " \t"), "+")
	not _next_leads_plus(lines, j)
}

_next_leads_plus(lines, j) if {
	j + 1 < count(lines)
	startswith(trim_left(lines[j + 1], " \t"), "+")
}

_dynamic(text) if regex.match(_concat, text)

_dynamic(text) if regex.match(_format, text)

_bad_arg(_, _, arg) if _dynamic(arg)

# A variable (or builder.toString()) assembled dynamically just above.
_bad_arg(lines, i, arg) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)(?:\.toString\(\))?\s*\)`, arg, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	_builds(lines, j, v)
}

_builds(lines, j, v) if {
	regex.match(concat("", [`\b`, v, `\s*(?:\+)?=[^=]`]), lines[j])
	text := _joined(lines, j)
	_dynamic(text)
	not regex.match(_sql_text, text)
}

# SQL text assembled for JDBC in a file that also uses an XQuery API.
_sql_text := `=\s*"\s*(?i:select|insert|update|delete|with|merge|call)\s`

_builds(lines, j, v) if {
	regex.match(concat("", [`^\s*`, v, `\.append\(`]), lines[j])
	regex.match(`\.append\(\s*[a-z_]`, lines[j])
}

# The argument is a new object other than a query: new HttpGet(url + ...).
_other_object(arg) if {
	m := regex.find_all_string_submatch_n(`^\s*new\s+(?:[\w.]+\.)?([A-Za-z_]\w*)\s*\(`, arg, 1)
	count(m) > 0
	not m[0][1] in {"XQuery", "QueryProcessor"}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_api, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:executeQuery|prepareExpression|executeCommand|compile|query|execute|newAdhocQuery)\s*\(|new\s+(?:XQuery|QueryProcessor)\s*\(`, line)
	not helpers.is_comment_line(line)
	stripped := _strip(line)
	sm := regex.find_all_string_submatch_n(_sink, stripped, 1)
	count(sm) > 0
	m := regex.find_all_string_submatch_n(_sink, line, 1)
	count(m) > 0
	arg := _arg(lines, i, m[0][1])
	not regex.match(`^\s*"\s*(?i:select|insert|update|delete|with)\s`, arg)
	not regex.match(`\bPattern\.compile\s*\(`, line)
	not _other_object(arg)
	_bad_arg(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "XQuery built from a non-constant value (concatenation or formatting) and executed: XQuery injection. Declare an external variable and bind the value with bindString/bindObject",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
