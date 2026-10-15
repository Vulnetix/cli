# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_643

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-643",
	"name": "XPath injection: query built from a dynamic string",
	"description": "An XPath query is built by splicing a variable into the expression text and then compiled or evaluated, so a value such as ' or '1'='1 rewrites the query (CWE-643). Reported in Java: javax.xml.xpath XPath.compile()/evaluate() on an XPath receiver (a variable declared as XPath, or named xpath/xp) and dom4j selectNodes()/selectSingleNode()/selectObject()/createXPath(); in Python: lxml .xpath() and etree.XPath(), elementpath.select()/iter_select(), and ElementTree find()/findall()/iterfind()/findtext() when the path has an XPath predicate. The expression argument (also when it starts on the next line) must be concatenation of a literal with a non-constant value, String.format/formatted/MessageFormat.format, a Python f-string with a placeholder, %-formatting or .format(), or a variable assigned from such an expression up to 20 lines above. Not reported: constant expressions (literals, ALL_CAPS constants), a single numeric %-conversion (\"%d\" % int(x)), parameterised queries (XPathVariableResolver, lxml $name variables bound by keyword), other evaluate() receivers (ScriptEngine, browser document.evaluate), comments and string literals. Whether the spliced value is attacker-controlled is not traced further than the building expression.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-643/",
	"languages": ["java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [643],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xpath-injection", "injection", "cwe-643"],
}

# ── Is an expression text built dynamically? ─────────────────────────────

_const(id) if regex.match(`^[A-Z][A-Z0-9_]*$`, id)

# A literal concatenated with a non-constant operand, on either side.
_built(s, _) if {
	some m in regex.find_all_string_submatch_n(`["']\s*\+\s*([A-Za-z_][\w.]*)`, s, -1)
	not _const(m[1])
}

_built(s, _) if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+\s*["']`, s, -1)
	not _const(m[1])
}

_built(s, "java") if regex.match(`\bString\.format\(|\.formatted\(|\bMessageFormat\.format\(|"\s*\)?\s*\.concat\(`, s)

# f-string with a placeholder that is not only constants.
_built(s, "py") if {
	some m in regex.find_all_string_submatch_n(`\b(?:[fF][rR]?|[rR][fF])("|')(?:\\.|[^\\])*?\{([^{}]+)\}`, s, -1)
	not _const(trim_space(m[2]))
}

_built(s, "py") if {
	regex.match(`["']\s*%\s*[\w(\[]`, s)
	# A single numeric conversion ("%d" % int(x)) cannot carry XPath syntax.
	not regex.match(`["']\s*%\s*(?:int|float|len)\([^()]*\)\s*\)?\s*$`, s)
}

_built(s, "py") if regex.match(`["']\s*\.format\(`, s)

# "".join(['/a[@id=\'', value, '\']']): a list with a bare name in it.
_built(s, "py") if regex.match(`["']\s*\.join\(\s*\[[^\]]*,\s*[a-z_]\w*\s*,`, s)

# ── Sinks: the expression argument text ──────────────────────────────────

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_gate("java", c) if regex.match(`XPath|selectNodes|selectSingleNode|selectObject|createXPath`, c)

_gate("py", c) if regex.match(`xpath|XPath|elementpath|ElementTree|etree`, c)

# Java XPath receiver: declared XPath in the file, or named after it.
_java_xpath_recv(_, r) if regex.match(`(?i)^(?:xp|\w*xpath\w*)$`, r)

_java_xpath_recv(content, r) if regex.match(concat("", [`\bXPath\s+`, r, `\b`]), content)

_sink(content, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\b(\w+)\.(?:compile|evaluate)\(\s*(.*)$`, line, 1)
	count(m) > 0
	_java_xpath_recv(content, m[0][1])
	rest := m[0][2]
}

_sink(_, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\bnewXPath\(\)\s*\.(?:compile|evaluate)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(_, line, "java") := rest if {
	m := regex.find_all_string_submatch_n(`\.(?:selectNodes|selectSingleNode|selectObject|createXPath)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(_, line, "py") := rest if {
	m := regex.find_all_string_submatch_n(`(?:\.xpath|\bXPath)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

# elementpath.select(root, path): the path is the second argument.
_sink(_, line, "py") := rest if {
	m := regex.find_all_string_submatch_n(`\belementpath\.(?:select|iter_select|Selector)\(\s*(?:[\w.]+\s*,\s*)?(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
}

_sink(content, line, "py") := rest if {
	regex.match(`ElementTree|etree`, content)
	m := regex.find_all_string_submatch_n(`\.(?:find|findall|iterfind|findtext)\(\s*(.*)$`, line, 1)
	count(m) > 0
	rest := m[0][1]
	regex.match(`\[\s*@|\[[\w.-]+\s*=`, rest)
}

# The argument text: the rest of the sink line, or the next code line when
# the call breaks right after its opening parenthesis.
_arg(_, _, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := lines[j] if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 2)
}

# A bare variable passed as the expression, built a few lines above.
_var_built(lines, i, arg, lang) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:[,)]|$)`, arg, 1)
	count(m) > 0
	v := m[0][1]
	re := concat("", [`^\s*(?:(?:final\s+)?[\w<>\[\]]+\s+)?`, v, `\s*=[^=]`])
	some j in numbers.range(max([0, i - 20]), i - 1)
	regex.match(re, lines[j])
	not helpers.is_comment_line(lines[j])
	_built(lines[j], lang)
}

_tainted(_, _, arg, lang) if _built(arg, lang)

_tainted(lines, i, arg, lang) if _var_built(lines, i, arg, lang)

# Python prose: a line that opens with a quote or sits in a docstring.
_prose(lines, i, "py") if regex.match(`^\s*[rbuf]?("|')`, lines[i])

_prose(lines, i, "py") if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
	n % 2 == 1
}

# The sink call itself sits inside a string literal.
_in_literal(line) if regex.match(`^[^"']*"[^"]*(?:\.xpath|XPath|evaluate|compile|select\w*|find\w*)\(`, line)

_in_literal(line) if regex.match(`^\s*\w+\s*=\s*["']`, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)xpath|evaluate\(|compile\(|select\w*\(|find\w*\(`, line)
	not helpers.is_comment_line(line)
	rest := _sink(content, line, lang)
	not _in_literal(line)
	arg := _arg(lines, i, rest)
	_tainted(lines, i, arg, lang)
	not _prose(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "XPath query built from a dynamic string: a value spliced into the expression can rewrite the query. Bind it as an XPath variable (XPathVariableResolver, lxml $name keyword arguments) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
